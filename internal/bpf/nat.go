package bpf

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Netopian/natbee/internal/comm"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type natElf struct {
	Prog         *ebpf.Program `ebpf:"nb_xdp_nat"`
	Service      *ebpf.Map     `ebpf:"nb_map_nat_service"`
	InRealServer *ebpf.Map     `ebpf:"nb_map_in_real_server"`
	RealServer   *ebpf.Map     `ebpf:"nb_map_nat_real_server"`
	Connection   *ebpf.Map     `ebpf:"nb_map_nat_connection"`
	Event        *ebpf.Map     `ebpf:"nb_map_nat_event"`
}

type nat struct {
	elf              natElf
	spec             *ebpf.CollectionSpec
	inRealServerSpec *ebpf.MapSpec
	inRealServer     sync.Map
	foreignConn      sync.Map
	ifIdx            sync.Map
	ticker           *time.Ticker
	rd               *perf.Reader
	close            chan struct{}
	timeout          uint32
}

func NewNAT(file string, timeout uint32) (comm.Service, error) {
	s := &nat{timeout: timeout}
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Errorf("remove mem lock failed: %v", err)
		return nil, err
	}

	specs, err := ebpf.LoadCollectionSpec(file)
	if err != nil {
		log.Errorf("load spec failed: %v", err)
		return nil, err
	}
	_, ok := specs.Maps[natRealServerMapName]
	if !ok {
		log.Errorf("load spec failed: map object[%s] missing", natRealServerMapName)
		return nil, fmt.Errorf("%s object missing", natRealServerMapName)
	}
	if s.inRealServerSpec, ok = specs.Maps[inRealServerMapName]; !ok {
		log.Errorf("load spec failed: map object[%s] missing", inRealServerMapName)
		return nil, fmt.Errorf("%s object missing", inRealServerMapName)
	}

	specs.Maps[natRealServerMapName].InnerMap = specs.Maps[inRealServerMapName]
	specs.Maps[natRealServerMapName].Extra = nil

	if err = specs.LoadAndAssign(&s.elf, nil); err != nil {
		log.Errorf("load bpf objects failed: %v", err)
		return nil, err
	}

	if s.rd, err = perf.NewReader(s.elf.Event, os.Getpagesize()); err != nil {
		log.Errorf("create perf reader failed: %v", err)
		return nil, err
	}

	log.Infof("services: %+v", s.elf.Service)
	log.Infof("real servers: %+v", s.elf.RealServer)
	log.Infof("connections: %+v", s.elf.Connection)

	s.close = make(chan struct{})
	s.ticker = time.NewTicker(comm.TickerTime)
	go s.recycle()
	go procEvent(s.rd)
	return s, nil
}

func (s *nat) Release() {
	s.rd.Close()
	close(s.close)
	s.elf.Prog.Close()
	s.elf.Service.Close()
	s.elf.Connection.Close()
	s.inRealServer.Range(func(k, v interface{}) bool {
		v.(*ebpf.Map).Close()
		return true
	})
	s.elf.RealServer.Close()
	s.elf.InRealServer.Close()
	s.elf.Event.Close()
}

func (s *nat) Add(key *comm.SrvKey, val *comm.SrvVal) error {
	k, err := key.Marshal()
	if err != nil {
		return errors.Wrap(err, "marshal nat key failed")
	}
	v, err := val.Marshal()
	if err != nil {
		return errors.Wrap(err, "marshal nat value failed")
	}

	inRsMap, err := createRealServerMap(s.inRealServerSpec, val)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			inRsMap.Close()
		}
	}()

	if err = s.elf.RealServer.Update(k, uint32(inRsMap.FD()), ebpf.UpdateNoExist); err != nil {
		return errors.Wrap(err, "put nat inner map failed")
	}

	if err = s.elf.Service.Update(k, v, ebpf.UpdateNoExist); err != nil {
		s.elf.RealServer.Delete(k)
		return errors.Wrap(err, "put nat service failed")
	}
	s.inRealServer.Store(*key, inRsMap)
	liteKey := *key
	liteKey.ParentIP = ""
	s.ifIdx.Store(liteKey, ifIdxInfo{uint32(val.VirtualIfIdx), uint32(val.LocalIfIdx)})
	return nil
}

func (s *nat) Del(key *comm.SrvKey) error {
	k, err := key.Marshal()
	if err != nil {
		return errors.Wrap(err, "marshal nat key failed")
	}
	if err = s.elf.Service.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return errors.Wrap(err, "delete nat service failed")
	}
	if err = s.elf.RealServer.Delete(k); err != nil {
		log.Errorf("del nat[%v] inner map failed: %+v", key, err)
	}
	if m, ok := s.inRealServer.LoadAndDelete(*key); ok {
		m.(*ebpf.Map).Close()
	}
	liteKey := *key
	liteKey.ParentIP = ""
	s.ifIdx.Delete(liteKey)
	return nil
}

func (s *nat) Attach(idx int) error {
	return comm.AttachLink(idx, s.elf.Prog.FD())
}

func (s *nat) Detach(idx int) error {
	return comm.DetachLink(idx)
}

// only keep positive connection
func (s *nat) PollSession() []*comm.Session {
	conns := pollConn(s.elf.Connection)
	ses := make([]*comm.Session, 0, len(conns)/2)
	for k, v := range conns {
		if v.IsPositive {
			se := comm.GetSession()
			se.FromConn(&k, v)
			ses = append(ses, se)
		}
	}
	return ses
}

func (s *nat) PushSession(ses []*comm.Session) {
	ts, err := comm.GetUptime()
	if err != nil {
		log.Errorf("get up time failed: %v", err)
		return
	}
	ts *= comm.NsCnt
	for _, v := range ses {
		af, err := comm.GetAddrFamily(v.CIP)
		if err != nil {
			log.Errorf("get %s address family failed: %v", v.CIP, err)
			continue
		}

		idxes, ok := s.ifIdx.Load(comm.SrvKey{IP: v.VIP, Port: v.VPort, Proto: v.Proto})
		if !ok {
			log.Errorf("get %s:%d interface indexes failed", v.VIP, v.VPort)
			continue
		}
		indexes := idxes.(ifIdxInfo)
		ks, vs := v.ToConn(af, indexes.virtualIfIdx, indexes.localIfIdx, ts)
		pushConn(s.elf.Connection, &s.foreignConn, ks, vs)
		se := v
		comm.PutSession(se)
	}
}

func (s *nat) recycle() {
	for {
		select {
		case <-s.close:
			return
		case <-s.ticker.C:
			staleConn(s.elf.Connection, &s.foreignConn, uint64(s.timeout), false)
		}
	}
}
