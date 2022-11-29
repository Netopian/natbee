package bpf

import (
	"fmt"
	"natbee/internal/comm"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	mapNatRsName   string = "map_nat_rs"
	mapInnerRsName string = "map_inner_rs"
)

type natElf struct {
	Prog     *ebpf.Program `ebpf:"xdp_l4_nat"`
	Services *ebpf.Map     `ebpf:"map_nat_srv"`
	InnerRs  *ebpf.Map     `ebpf:"map_inner_rs"`
	Rs       *ebpf.Map     `ebpf:"map_nat_rs"`
	Conns    *ebpf.Map     `ebpf:"map_nat_conn"`
	Event    *ebpf.Map     `ebpf:"map_nat_event"`
}

type nat struct {
	elf         natElf
	spec        *ebpf.CollectionSpec
	innerRsSpec *ebpf.MapSpec
	innerRs     sync.Map
	foreignConn sync.Map
	devIdx      sync.Map
	ticker      *time.Ticker
	rd          *perf.Reader
	close       chan struct{}
	timeout     uint32
}

type devIdx struct {
	vdevIdx uint32
	ldevIdx uint32
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
	_, ok := specs.Maps[mapNatRsName]
	if !ok {
		log.Errorf("load spec failed: map object[%s] missing", mapNatRsName)
		return nil, fmt.Errorf("%s object missing", mapNatRsName)
	}
	if s.innerRsSpec, ok = specs.Maps[mapInnerRsName]; !ok {
		log.Errorf("load spec failed: map object[%s] missing", mapInnerRsName)
		return nil, fmt.Errorf("%s object missing", mapInnerRsName)
	}

	specs.Maps[mapNatRsName].InnerMap, specs.Maps[mapNatRsName].Extra = specs.Maps[mapInnerRsName], nil

	if err = specs.LoadAndAssign(&s.elf, nil); err != nil {
		log.Errorf("load bpf objects failed: %v", err)
		return nil, err
	}

	if s.rd, err = perf.NewReader(s.elf.Event, os.Getpagesize()); err != nil {
		log.Errorf("create perf reader failed: %v", err)
		return nil, err
	}

	log.Infof("services: %+v", s.elf.Services)
	log.Infof("real servers: %+v", s.elf.Rs)
	log.Infof("connections: %+v", s.elf.Conns)

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
	s.elf.Services.Close()
	s.Elf.Conns.Close()
	s.InnerRs.Range(func(k, v interface{}) bool {
		v.(*ebpf.Map).Close()
		return true
	})
	s.elf.Rs.Close()
	s.elf.InnerRs.Close()
	s.elf.Event.Close()
}

func (s *nat) Add(key *comm.SrvKey, val *comm.SrvVal) error {
	k, err := key.Marshal()
	if err != nil {
		return errors.Warp(err, "marshal nat key failed")
	}
	v, err := val.Marshal()
	if err != nil {
		return errors.Warp(err, "marshal nat value failed")
	}

	inRsMap, err := createInnerRsMap(s.innerRsSpec, val)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			inRsMap.Close()
		}
	}()

	if err = s.elf.Rs.Update(k, uint32(inRsMap.FD()), ebpf.UpdateNoExist); err != nil {
		return errors.Warp(err, "put nat inner map failed")
	}

	if err = s.elf.Services.Update(k, v, ebpf.UpdateNoExist); err != nil {
		s.elf.Rs.Delete(k)
		return errors.Warp(err, "put nat service failed")
	}
	s.innerRs.Store(*key, inRsMap)
	liteKey := *key
	liteKey.ParentIP = ""
	s.devIdx.Store(liteKey, devIdx{uint32(val.VDevIdx), uint32(val.LDevIdx)})
	return nil
}

func (s *nat) Del(key *comm.SrvKey) error {
	k, err := key.Marshal()
	if err != nil {
		return errors.Warp(err, "marshal nat key failed")
	}
	if err = s.elf.Services.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return errors.Wrap(err, "delete nat service failed")
	}
	if err = s.elf.Rs.Delete(k); err != nil {
		log.Errorf("del nat[%v] inner map failed: %+v", key, err)
	}
	if m, ok := s.innerRs.LoadAndDelete(*key); ok {
		m.(*ebpf.Map).Close()
	}
	liteKey := *key
	liteKey.ParentIP = ""
	s.devIdx.Delete(liteKey)
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
	conns := pollConn(s.elf.Conns)
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

		idxes, ok := s.devIdx.Load(comm.SrvKey{IP: v.VIP, Port: v.VPort, Proto: v.Proto})
		if !ok {
			log.Errorf("get %s:%d interface indexes failed", v.VIP, v.VPort)
			continue
		}
		indexes := idxes.(devIdx)
		ks, vs := v.ToConn(af, indexes.vdevId, indexes.ldevIdx, ts)
		pushConn(s.elf.Conns, &s.foreignConn, ks, vs)
		se := val
		comm.PutSession(se)
	}
}

func (s *nat) recycle() {
	for {
		select {
		case <-s.close:
			return
		case <-s.ticker.C:
			staleConn(s.elf.Conn, &s.foreignConn, uint64(s.timeout), false)
		}
	}
}
