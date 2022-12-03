package bpf

import (
	"natbee/internal/comm"
	"natbee/internal/netraw"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
)

const (
	connHashMapSz int = 1 << 13
)

var (
	connValPool *sync.Pool
)

func init() {
	connValPool = &sync.Pool{
		New: func() interface{} { return new(comm.ConnVal) },
	}
}

func getConnVal() *comm.ConnVal {
	return connValPool.Get().(*comm.ConnVal)
}

func putConnVal(v *comm.ConnVal) {
	connValPool.Put(v)
}

func createInnerRsMap(spec *ebpf.MapSpec, val *comm.SrvVal) (*ebpf.Map, error) {
	rsIps, err := comm.StrArrToIpArr(val.RsIps)
	if err != nil {
		return nil, errors.Wrap(err, "create inner real server map failed")
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, errors.Wrap(err, "create inner real server map failed")
	}
	cpuNum := runtime.NumCPU()
	b, i := make([]byte, comm.MapRealServerSz), 0
	for ; i < len(rsIps); i++ {
		comm.PutBeAddr(b, val.Proto, rsIps[i], 0)
		comm.PutUint32(b[comm.MapAddrSz:], uint32(0))
		if err = m.Put(uint32(i), b); err != nil {
			err = errors.Wrap(err, "put %s failed", m.String())
			return nil, err
		}
	}
	for ; i < cpuNum; i++ {
		comm.PutUint32(b[comm.MapAddrSz:], uint32(0))
		if err = m.Put(uint32(i), b); err != nil {
			err = errors.Wrap(err, "put %s failed", m.String())
			return nil, err
		}
	}
	return m, nil
}

// if exclusive mode, will return ports to release
func staleConn(m *ebpf.Map, mc *sync.Map, timeout uint64, exclusive bool) []uint32 {
	conns := pollConn(m)
	filterStaledConn(mc, &conns, timeout)
	ports := []uint32{}
	var err error
	key := make([]byte, comm.MapConnKeySz)
	for k, v := range conns {
		for {
			if v.IsPositive {
				mc.Delete(k)
			}
			if key, err = k.Marshal(); err != nil {
				log.Errorf("marshal %s key failed: %v", m.String(), err)
				break
			}
			m.Delete(key)
			if !exclusive || !v.IsLocalPort {
				break
			}
			ports = append(ports, uint32(k.RxDPort))
			break
		}
		putConnVal(v)
	}
	return ports
}

func filterStaledConn(mc *sync.Map, conns *map[comm.ConnKey]*comm.ConnVal, timeout uint64) {
	cur, err := comm.GetUptime()
	if err != nil {
		log.Errorf("get system boot time failed: %v", err)
		*conns = make(map[comm.ConnKey]*comm.ConnVal)
		return
	}
	for k, v := range *conns {
		k1, k2 := k, comm.ConnKey{Af: k.Af, Proto: k.Proto,
			RxSIP: v.TxDIP, RxSPort: v.TxDPort, RxDIP: v.TxSIP, RxDPort: v.TxSPort}
		ts := v.Ts / comm.NsCnt
		if !v.IsLocal && v.IsPositive {
			if t, ok := mc.Load(k); ok {
				ts = t.(uint64) / comm.NsCnt
			}
		}
		if ts+timeout >= cur {
			delete(*conns, k1)
			putConnVal(v)
			if v2, ok := (*conns)[k2]; ok {
				delete(*conns, k2)
				putConnVal(v2)
			}
		}
	}
}

func pollConn(m *ebpf.Map) map[comm.ConnKey]*comm.ConnVal {
	conns := make(map[comm.ConnKey]*comm.ConnVal, connHashMapSz)
	k := make([]byte, comm.MapConnKeySz)
	v := make([]byte, comm.MapConnValSz)
	it := m.Iterate()
	for it.Next(&k, &v) {
		key, val := comm.ConnKey{}, getConnVal()
		if err := key.Unmarshal(k); err != nil {
			log.Errorf("unmarshal %s key failed: %v", m.String(), err)
			continue
		}
		if err := val.Unmarshal(v); err != nil {
			log.Errorf("unmarshal %s value failed: %v", m.String(), err)
			continue
		}
		conns[key] = val
	}
	return conns
}

func pushConn(m *ebpf.Map, mc *sync.Map, ks []comm.ConnKey, vs []comm.ConnVal) {
	key1, err := ks[0].Marshal()
	if err != nil {
		log.Errorf("marshal connection key failed: %v", err)
		return
	}
	key2, err := ks[1].Marshal()
	if err != nil {
		log.Errorf("marshal connection key failed: %v", err)
		return
	}
	val1, err := vs[0].Marshal()
	if err != nil {
		log.Errorf("marshal connection value failed: %v", err)
		return
	}
	val2, err := vs[1].Marshal()
	if err != nil {
		log.Errorf("marshal connection value failed: %v", err)
		return
	}
	mc.Store(ks[0], vs[0].Ts)
	if err = m.Update(key1, val1, ebpf.UpdateNoExist); err != nil {
		return
	}
	if err = m.Update(key2, val2, ebpf.UpdateNoExist); err != nil {
		m.Delete(key1)
	}
}

func procEvent(rd *perf.Reader) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Errorf("reading from reader failed: %v", err)
			continue
		}
		if len(record.RawSample) < comm.MapConnKeySz {
			continue
		}
		dstIP, _, _ := comm.GetBeAddr(record.RawSample[comm.MapAddrSz:])
		netraw.Ping(dstIP)
	}
}
