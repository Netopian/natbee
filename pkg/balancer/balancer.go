package balancer

import (
	"fmt"
	"natbee/internal/bpf"
	"natbee/internal/comm"
	"natbee/internal/intf"
	"natbee/pkg/config"
	"sync"

	"github.com/pkg/errors"
)

type Balancer struct {
	nat      comm.Service
	fnat     comm.Service
	attached sync.Map
	services sync.Map
	conf     *config.ConfigSet
}

type attachInfo struct {
	mode comm.BpfMode
}

func NewBalancer(conf *config.ConfigSet) (*Balancer, error) {
	var err error
	if err = intf.RefreshInterfaces(); err != nil {
		return nil, errors.Wrap(err, "refresh interfacees failed")
	}
	b := &Balancer{conf: conf}

	if len(conf.Global.NatFilePath) > 0 {
		b.nat, err = bpf.NewNAT(conf.Global.NatFilePath, conf.Global.ConnTimeout)
		if err != nil {
			return nil, errors.Wrap(err, "load nat elf failed")
		}
	}

	if len(conf.Global.FNatFilePath) > 0 {
		b.fnat, err = bpf.NewNAT(conf.Global.FNatFilePath, conf.Global.ConnTimeout)
		if err != nil {
			return nil, errors.Wrap(err, "load fnat elf failed")
		}
	}

	if err = b.loadService(); err != nil {
		b.Release()
		return nil, errors.Wrap(err, "load service failed")
	}
	return b, nil
}

func (b *Balancer) Release() {
	if b.nat != nil {
		b.nat.Release()
	}
	if b.fnat != nil {
		b.fnat.Release()
	}
	b.attached.Range(func(k, v interface{}) bool {
		devIdx, ok := k.(int)
		if !ok {
			return true
		}
		info, ok := v.(*attachInfo)
		if !ok {
			return true
		}
		switch info.mode {
		case comm.ModeNat:
			b.nat.Detach(devIdx)
		case comm.ModeFNat:
			b.fnat.Detach(devIdx)
		}
		return true
	})
}

func (b *Balancer) AttachNat(ip string) error {
	if err := b.attach(ip, comm.ModeNat); err != nil {
		return err
	}
	b.conf.AttachNat(ip)
	return nil
}

func (b *Balancer) DetachNat(ip string) error {
	if err := b.detach(ip, comm.ModeNat); err != nil {
		return err
	}
	b.conf.DetachNat(ip)
	return nil
}

func (b *Balancer) AddNat(k *comm.SrvKey, v *comm.SrvVal) error {
	if err := b.add(k, v, comm.ModeNat); err != nil {
		return err
	}
	b.conf.AddNat(config.Service{
		VirtualIP:     comm.JoinIP(k.IP, k.ParentIP),
		VirtualPort:   uint32(k.Port),
		Protocol:      k.Proto.String(),
		LocalIP:       v.LIP,
		RealPort:      uint32(v.RPort),
		RealServerIPs: v.RsIps,
	})
	return nil
}

func (b *Balancer) DelNat(k *comm.SrvKey) error {
	if err := b.del(k, comm.ModeNat); err != nil {
		return err
	}
	b.conf.DelNat(config.Service{
		VirtualIP:   comm.JoinIP(k.IP, k.ParentIP),
		VirtualPort: uint32(k.Port),
		Protocol:    k.Proto.String(),
	})
	return nil
}

func (b *Balancer) PollNatSesssion() ([]*comm.Session, error) {
	if b.nat == nil {
		return nil, errors.New("not support nat")
	}
	return b.nat.PollSession(), nil
}

func (b *Balancer) PushNatSession(ses []*comm.Session) error {
	if b.nat == nil {
		return errors.New("not support nat")
	}
	b.nat.PushSession(ses)
	return nil
}

/////
func (b *Balancer) AttachFNat(ip string) error {
	if err := b.attach(ip, comm.ModeFNat); err != nil {
		return err
	}
	b.conf.AttachFNat(ip)
	return nil
}

func (b *Balancer) DetachFNat(ip string) error {
	if err := b.detach(ip, comm.ModeFNat); err != nil {
		return err
	}
	b.conf.DetachFNat(ip)
	return nil
}

func (b *Balancer) AddFNat(k *comm.SrvKey, v *comm.SrvVal) error {
	if err := b.add(k, v, comm.ModeFNat); err != nil {
		return err
	}
	b.conf.AddFNat(config.Service{
		VirtualIP:     comm.JoinIP(k.IP, k.ParentIP),
		VirtualPort:   uint32(k.Port),
		Protocol:      k.Proto.String(),
		LocalIP:       v.LIP,
		RealPort:      uint32(v.RPort),
		RealServerIPs: v.RsIps,
	})
	return nil
}

func (b *Balancer) DelFNat(k *comm.SrvKey) error {
	if err := b.del(k, comm.ModeFNat); err != nil {
		return err
	}
	b.conf.DelFNat(config.Service{
		VirtualIP:   comm.JoinIP(k.IP, k.ParentIP),
		VirtualPort: uint32(k.Port),
		Protocol:    k.Proto.String(),
	})
	return nil
}

func (b *Balancer) PollFNatSesssion() ([]*comm.Session, error) {
	if b.fnat == nil {
		return nil, errors.New("not support fnat")
	}
	return b.fnat.PollSession(), nil
}

func (b *Balancer) PushFNatSession(ses []*comm.Session) error {
	if b.fnat == nil {
		return errors.New("not support fnat")
	}
	b.fnat.PushSession(ses)
	return nil
}

func (b *Balancer) loadService() error {
	for _, v := range b.conf.Nat.Attached {
		if err := b.attach(v, comm.ModeNat); err != nil {
			return err
		}
	}
	for _, v := range b.conf.Nat.Services {
		key, val, err := genSrvKeyVal(v, comm.ModeNat)
		if err != nil {
			return err
		}
		if err = b.add(key, val, comm.ModeNat); err != nil {
			return err
		}
	}
	///
	for _, v := range b.conf.FNat.Attached {
		if err := b.attach(v, comm.ModeFNat); err != nil {
			return err
		}
	}
	for _, v := range b.conf.FNat.Services {
		key, val, err := genSrvKeyVal(v, comm.ModeFNat)
		if err != nil {
			return err
		}
		if err = b.add(key, val, comm.ModeFNat); err != nil {
			return err
		}
	}
	return nil
}

func (b *Balancer) attach(ip string, mode comm.BpfMode) error {
	devIdx, err := intf.GetIfIdxByIp(ip)
	if err != nil {
		return err
	}

	switch mode {
	case comm.ModeNat:
		if b.nat == nil {
			err = errors.New("not support nat")
		} else {
			err = b.nat.Attach(devIdx)
		}
	case comm.ModeFNat:
		if b.fnat == nil {
			err = errors.New("not support fnat")
		} else {
			err = b.fnat.Attach(devIdx)
		}
	default:
		err = errors.New("not support mode")
	}
	if err != nil {
		return errors.Wrap(err, "attach failed")
	}
	b.attached.Store(devIdx, &attachInfo{mode: mode})
	return nil
}

func (b *Balancer) detach(ip string, mode comm.BpfMode) error {
	devIdx, err := intf.GetIfIdxByIp(ip)
	if err != nil {
		return err
	}
	if v, ok := b.attached.Load(devIdx); !ok {
		return nil
	} else if v.(*attachInfo).mode != mode {
		return nil
	}

	switch mode {
	case comm.ModeNat:
		if b.nat == nil {
			err = errors.New("not support nat")
		} else {
			err = b.nat.Detach(devIdx)
		}
	case comm.ModeFNat:
		if b.fnat == nil {
			err = errors.New("not support fnat")
		} else {
			err = b.fnat.Detach(devIdx)
		}
	default:
		err = errors.New("not support mode")
	}
	if err != nil {
		return errors.Wrap(err, "detach failed")
	}
	b.attached.Delete(devIdx)
	return nil
}

func (b *Balancer) add(k *comm.SrvKey, v *comm.SrvVal, mode comm.BpfMode) error {
	if val, ok := b.attached.Load(v.VDevIdx); !ok || val.(*attachInfo).mode != mode {
		return fmt.Errorf("interface[%d] not attached or mode is mismatched", v.VDevIdx)
	}
	if _, exist := b.services.LoadOrStore(k, v); exist {
		return errors.New("service exist")
	}

	var err error
	switch mode {
	case comm.ModeNat:
		if b.nat == nil {
			err = errors.New("not support nat")
		} else {
			err = b.nat.Add(k, v)
		}
	case comm.ModeFNat:
		if b.fnat == nil {
			err = errors.New("not support fnat")
		} else {
			err = b.fnat.Add(k, v)
		}
	default:
		err = errors.New("not support mode")
	}
	if err != nil {
		b.services.Delete(k)
		return errors.Wrap(err, "add service failed")
	}
	return nil
}

func (b *Balancer) del(k *comm.SrvKey, mode comm.BpfMode) error {
	if _, ok := b.services.Load(k); !ok {
		return nil
	}

	var err error
	switch mode {
	case comm.ModeNat:
		if b.nat == nil {
			err = errors.New("not support nat")
		} else {
			err = b.nat.Del(k)
		}
	case comm.ModeFNat:
		if b.fnat == nil {
			err = errors.New("not support fnat")
		} else {
			err = b.fnat.Del(k)
		}
	default:
		err = errors.New("not support mode")
	}
	if err != nil {
		return errors.Wrap(err, "delete service failed")
	}
	b.services.Delete(k)
	return nil
}

func genSrvKeyVal(s config.Service, mode comm.BpfMode) (*comm.SrvKey, *comm.SrvVal, error) {
	var err error
	k := &comm.SrvKey{Port: uint16(s.VirtualPort)}
	k.IP, k.ParentIP = comm.SplitIP(s.VirtualIP)
	if k.Proto, err = comm.SockProtoValue(s.Protocol); err != nil {
		return nil, nil, err
	}
	v := &comm.SrvVal{
		Proto: k.Proto,
		Mode:  mode,
		RPort: uint16(s.RealPort),
		RsIps: s.RealServerIPs,
	}
	v.LIP, v.ParentLIP = comm.SplitIP(s.LocalIP)
	if len(k.ParentIP) == 0 {
		if v.VDevIdx, err = intf.GetIfIdxByIp(k.IP); err != nil {
			return nil, nil, errors.Wrapf(err, "get virtual ip(%s) interface index failed", k.IP)
		}
	} else {
		if v.VDevIdx, err = intf.GetIfIdxByIp(k.ParentIP); err != nil {
			return nil, nil, errors.Wrapf(err, "get parent virtual ip(%s) interface index failed", k.ParentIP)
		}
	}
	if len(v.ParentLIP) == 0 {
		if v.LDevIdx, err = intf.GetIfIdxByIp(v.LIP); err != nil {
			return nil, nil, errors.Wrapf(err, "get local ip(%s) interface index failed", v.LIP)
		}
	} else {
		if v.LDevIdx, err = intf.GetIfIdxByIp(v.ParentLIP); err != nil {
			return nil, nil, errors.Wrapf(err, "get parent local ip(%s) interface index failed", v.ParentLIP)
		}
	}
	return k, v, nil
}
