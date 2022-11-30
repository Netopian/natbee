package bpf

import (
	"fmt"
	"natbee/internal/comm"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	mapFNatRsName    string = "map_fnat_rs"
	mapInnerPortName string = "map_inner_port"
	mapFNatPortName  string = "map_fnat_port"
	startPort        uint32 = 5001
	portsCnt         int    = 60000
	szIdx            uint32 = 65535
	getIdx           uint32 = 65533
	putIdx           uint32 = 65534
)

type fnatElf struct {
	XdpProg     *ebpf.Program `ebpf:"xdp_l4_fnat"`
	TcProg      *ebpf.Program `ebpf:"tc_l4_fnat"`
	Services    *ebpf.Map     `ebpf:"map_fnat_srv"`
	InnerRs     *ebpf.Map     `ebpf:"map_inner_rs"`
	Rs          *ebpf.Map     `ebpf:"map_fnat_rs"`
	Conns       *ebpf.Map     `ebpf:"map_fnat_conn"`
	InnerPort   *ebpf.Map     `ebpf:"map_inner_port"`
	Port        *ebpf.Map     `ebpf:"map_fnat_port"`
	ReleasePort *ebpf.Map     `ebpf:"map_fnat_release_port"`
	Event       *ebpf.Map     `ebpf:"map_fnat_event"`
}

type fnat struct {
	elf           fnatElf
	spec          *ebpf.CollectionSpec
	innerRsSpec   *ebpf.MapSpec
	innerRs       sync.Map
	innerPortSpec *ebpf.MapSpec
	innerPort     sync.Map
	foreignConn   sync.Map
	devIdx        sync.Map
	portPoolSz    uint32
	ticker        *time.Ticker
	rd            *perf.Reader
	close         chan struct{}
	exclusive     bool
	timeout       uint32
	useTc         bool
}

type devIdx struct {
	vdevIdx uint32
	ldevIdx uint32
}

func NewFNAT(file string, timeout uint32, exclusive bool, useTc bool) (comm.Service, error) {
	s := &fnat{timeout: timeout, exclusive: exclusive, useTc: useTc}
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
	_, ok := specs.Maps[mapFNatRsName]
	if !ok {
		log.Errorf("load spec failed: map object[%s] missing", mapFNatRsName)
		return nil, fmt.Errorf("%s object missing", mapFNatRsName)
	}
	if s.innerRsSpec, ok = specs.Maps[mapInnerRsName]; !ok {
		log.Errorf("load spec failed: map object[%s] missing", mapInnerRsName)
		return nil, fmt.Errorf("%s object missing", mapInnerRsName)
	}
	if _, ok := specs.Maps[mapFNatPortName]; !ok {
		log.Errorf("load spec failed: map object[%s] missing", mapFNatPortName)
		return nil, fmt.Errorf("%s object missing", mapFNatPortName)
	}
	if s.innerPortSpec, ok = specs.Maps[mapInnerPortName]; !ok {
		log.Errorf("load spec failed: map object[%s] missing", mapInnerPortName)
		return nil, fmt.Errorf("%s object missing", mapInnerPortName)
	}

	specs.Maps[mapFNatRsName].InnerMap, specs.Maps[mapFNatRsName].Extra = specs.Maps[mapInnerRsName], nil
	specs.Maps[mapFNatPortName].InnerMap, specs.Maps[mapFNatPortName].Extra = specs.Maps[mapInnerPortName], nil

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
	if err = s.initPortMap(); err != nil {
		s.deinitPortMap()
		log.Errorf("init port map failed: %v", err)
		return nil, err
	}

	s.close = make(chan struct{})
	s.ticker = time.NewTicker(comm.TickerTime)
	go s.recycle()
	go procEvent(s.rd)
	return s, nil
}

func (s *fnat) Release() {
	s.rd.Close()
	close(s.close)
	s.elf.XdpProg.Close()
	s.elf.TcProg.Close()
	s.elf.Services.Close()
	s.elf.Conns.Close()
	s.innerRs.Range(func(k, v interface{}) bool {
		v.(*ebpf.Map).Close()
		return true
	})
	s.elf.Rs.Close()
	s.elf.InnerRs.Close()
	s.deinitPortMap()
	s.elf.Port.Close()
	s.elf.InnerPort.Close()
	s.elf.Event.Close()
}

func (s *fnat) Add(key *comm.SrvKey, val *comm.SrvVal) error {
	k, err := key.Marshal()
	if err != nil {
		return errors.Warp(err, "marshal fnat key failed")
	}
	v, err := val.Marshal()
	if err != nil {
		return errors.Warp(err, "marshal fnat value failed")
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
		return errors.Warp(err, "put fnat inner map failed")
	}

	if err = s.elf.Services.Update(k, v, ebpf.UpdateNoExist); err != nil {
		s.elf.Rs.Delete(k)
		return errors.Warp(err, "put fnat service failed")
	}
	s.innerRs.Store(*key, inRsMap)
	liteKey := *key
	liteKey.ParentIP = ""
	s.devIdx.Store(liteKey, devIdx{uint32(val.VDevIdx), uint32(val.LDevIdx)})
	return nil
}

func (s *fnat) Del(key *comm.SrvKey) error {
	k, err := key.Marshal()
	if err != nil {
		return errors.Warp(err, "marshal fnat key failed")
	}
	if err = s.elf.Services.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return errors.Wrap(err, "delete fnat service failed")
	}
	if err = s.elf.Rs.Delete(k); err != nil {
		log.Errorf("del fnat[%v] inner map failed: %+v", key, err)
	}
	if m, ok := s.innerRs.LoadAndDelete(*key); ok {
		m.(*ebpf.Map).Close()
	}
	liteKey := *key
	liteKey.ParentIP = ""
	s.devIdx.Delete(liteKey)
	return nil
}

func (s *fnat) Attach(idx int) error {
	if s.useTc {
		return comm.AddFilter(idx, s.elf.TcProg.FD())
	}
	return comm.AttachLink(idx, s.elf.XdpProg.FD())
}

func (s *fnat) Detach(idx int) error {
	if s.useTc {
		return comm.DelFilter(idx)
	}
	return comm.DetachLink(idx)
}

// only keep positive connection
func (s *fnat) PollSession() []*comm.Session {
	conns := pollConn(s.elf.Conns)
	ses := make([]*comm.Session, 0, len(conns)/2)
	for k, v := range conns {
		delVal := v
		if v.IsPositive {
			se := comm.GetSession()
			se.FromConn(&k, v)
			ses = append(ses, se)
		}
		putConnVal(delVal)
	}
	return ses
}

func (s *fnat) PushSession(ses []*comm.Session) {
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
		se := v
		comm.PutSession(se)
	}
}

func (s *fnat) recycle() {
	for {
		select {
		case <-s.close:
			return
		case <-s.ticker.C:
			ports := staleConn(s.elf.Conn, &s.foreignConn, uint64(s.timeout), s.exclusive)
			s.releasePorts(ports)
		}
	}
}

// exclusive port mode func below
func (s *fnat) initPortMap() error {
	if !s.exclusive {
		return nil
	}
	cpuNum := runtime.NumCPU()
	s.portPoolSz = uint32(portsCnt / cpuNum)
	port := uint32(startPort)
	for i := 0; i < cpuNum; i++ {
		m, err := ebpf.NewMap(s.innerPortSpec)
		if err != nil {
			return errors.Wrap(err, "create port map failed")
		}
		for j := uint32(0); j < s.portPoolSz; j++ {
			m.Put(j, port)
			port++
		}
		m.Put(getIdx, uint32(0))
		m.Put(putIdx, uint32(0))
		m.Put(szIdx, uint32(s.portPoolSz))
		if err = s.elf.Port.Update(uint32(i), uint32(m.FD()), ebpf.UpdateNoExist); err != nil {
			m.Close()
			return errors.Wrap(err, "put fnat inner map failed")
		}
		s.innerPort.Store(i, m)
	}
	log.Infof("cpu num is %d", cpuNum)
	return nil
}

func (s *fnat) deinitPortMap() {
	if !s.exclusive {
		return
	}
	s.innerPort.Range(func(k, v interface{}) bool {
		v.(*ebpf.Map).Close()
		return true
	})
}

// release input and ebpf map together
func (s *fnat) releasePorts(ports []uint32) {
	var k, v uint32
	it := s.elf.ReleasePort.Iterate()
	for it.Next(&k, &v) {
		s.releasePort(k)
	}
	for _, p := range ports {
		s.releasePort(p)
	}
}

func (s *fnat) releasePort(port uint32) {
	cpu := uint32(port-startPort) / s.portPoolSz
	m, ok := s.innerPort.Load(int(cpu))
	if !ok {
		return
	}
	var idx uint32
	if err := m.(*ebpf.Map).Lookup(putIdx, &idx); err != nil {
		log.Errorf("release port - get put-index failed: %v", err)
		return
	}
	if err := m.(*ebpf.Map).Put(idx, uint32(port)); err != nil {
		log.Errorf("release port - put port failed: %v", err)
		return
	}
	idx = (idx + 1) % uint32(s.portPoolSz)
	if err := m.(*ebpf.Map).Put(putIdx, idx); err != nil {
		log.Errorf("release port - put put-index failed: %v", err)
	}
}
