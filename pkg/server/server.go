package server

import (
	"context"
	"fmt"
	"natbee/internal/comm"
	"natbee/internal/intf"
	"natbee/pkg/balancer"
	"natbee/pkg/config"
	"net"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	api "natbee/api"

	"github.com/pkg/errors"
)

type server struct {
	grpcServer *grpc.Server
	b          *balancer.Balancer
	c          *config.ConfigSet
	port       uint16
}

func NewAPIServer(g *grpc.Server, b *balancer.Balancer, c *config.ConfigSet, port uint16) *server {
	grpc.EnableTracing = false
	s := &server{
		grpcServer: g,
		b:          b,
		c:          c,
		port:       port,
	}
	api.RegisterNatbeeApiServer(g, s)
	return s
}

func (s *server) Serve() error {
	address := fmt.Sprintf("%d", s.port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Warn("listen failed")
		return err
	}

	serve := func(listener net.Listener) {
		e := s.grpcServer.Serve(listener)
		log.Warnf("accept failed: %v", e)
	}

	go serve(listener)
	return nil
}

func (s *server) Attach(c context.Context, r *api.AttachRequest) (*api.Empty, error) {
	var (
		err error
	)

	switch r.Type {
	case api.ServiceType_NAT:
		err = s.b.AttachNat(r.Ip)
	case api.ServiceType_FNAT:
		err = s.b.AttachFNat(r.Ip)
	default:
		err = errors.New("invalid service type")
	}

	if err != nil {
		log.Errorf("attach [%s] failed: %v", r.Ip, err)

	} else {
		log.Infof("attach [%s] success", r.Ip)
	}
	return &api.Empty{}, err
}

func (s *server) Detach(c context.Context, r *api.AttachRequest) (*api.Empty, error) {
	var (
		err error
	)

	switch r.Type {
	case api.ServiceType_NAT:
		err = s.b.DetachNat(r.Ip)
	case api.ServiceType_FNAT:
		err = s.b.DetachFNat(r.Ip)
	default:
		err = errors.New("invalid service type")
	}

	if err != nil {
		log.Errorf("detach [%s] failed: %v", r.Ip, err)

	} else {
		log.Infof("detach [%s] success", r.Ip)
	}
	return &api.Empty{}, err
}

func (s *server) AddService(c context.Context, r *api.AddRequest) (*api.Empty, error) {
	var (
		err error
		k   *comm.SrvKey
		v   *comm.SrvVal
	)

	for {
		if k, err = genSrvKey(r.Key); err != nil {
			break
		}
		if v, err = genSrvVal(k.IP, k.ParentIP, k.Proto, r.Val); err != nil {
			break
		}
		switch r.Type {
		case api.ServiceType_NAT:
			err = s.b.AddNat(k, v)
		case api.ServiceType_FNAT:
			err = s.b.AddFNat(k, v)
		default:
			err = errors.New("invalid service type")
		}
		if err != nil {
			break
		}
		log.Infof("add service [%s:%d] success", r.Key.Ip, r.Key.Port)
		return &api.Empty{}, nil
	}
	log.Errorf("add service [%s:%d] failed: %v", r.Key.Ip, r.Key.Port, err)
	return nil, err
}

func (s *server) DelService(c context.Context, r *api.DelRequest) (*api.Empty, error) {
	var (
		err error
		k   *comm.SrvKey
	)

	for {
		if k, err = genSrvKey(r.Key); err != nil {
			break
		}
		switch r.Type {
		case api.ServiceType_NAT:
			err = s.b.DelNat(k)
		case api.ServiceType_FNAT:
			err = s.b.DelFNat(k)
		default:
			err = errors.New("invalid service type")
		}
		if err != nil {
			break
		}
		log.Infof("delete service [%s:%d] success", r.Key.Ip, r.Key.Port)
		return &api.Empty{}, nil
	}
	log.Errorf("delete service [%s:%d] failed: %v", r.Key.Ip, r.Key.Port, err)
	return nil, err
}

func (s *server) Save(c context.Context, r *api.SaveReq) (*api.Empty, error) {
	if err := s.c.Save(r.FilePath); err != nil {
		return nil, err
	}
	return &api.Empty{}, nil
}

func (s *server) Poll(c context.Context, r *api.PollRequest) (*api.PollResponse, error) {
	var (
		natSes  []*comm.Session
		fnatSes []*comm.Session
	)
	resp := &api.PollResponse{TransportGroup: s.c.Global.Group}
	switch r.Type {
	case api.ServiceType_DEFAULT:
		// only keep local session
		natSes, _ = s.b.PollNatSesssion()
		resp.NatSessions = genAPISession(natSes, true)
		fnatSes, _ = s.b.PollFNatSesssion()
		resp.FnatSessions = genAPISession(fnatSes, true)
	case api.ServiceType_NAT:
		natSes, _ = s.b.PollNatSesssion()
		resp.NatSessions = genAPISession(natSes, false)
	case api.ServiceType_FNAT:
		fnatSes, _ = s.b.PollFNatSesssion()
		resp.FnatSessions = genAPISession(fnatSes, false)
	default:
		return nil, errors.New("invalid service type")
	}
	return resp, nil
}

func (s *server) Push(c context.Context, r *api.PushRequest) (*api.Empty, error) {
	if r.TransportGroup != s.c.Global.Group {
		return nil, errors.New("group mismatch")
	}
	natSes := genSession(r.NatSessions)
	fnatSes := genSession(r.FnatSessions)
	s.b.PushNatSession(natSes)
	s.b.PushFNatSession(fnatSes)
	return &api.Empty{}, nil
}

func genSrvKey(key *api.SockAddr) (*comm.SrvKey, error) {
	k := &comm.SrvKey{
		Port:  uint16(key.Port),
		Proto: comm.SockProto(key.Protocol),
	}
	k.IP, k.ParentIP = comm.SplitIP(key.Ip)
	if !k.Proto.Valid() {
		return nil, errors.New("invalid protocol")
	}
	return k, nil
}

func genSrvVal(vip, pvip string, proto comm.SockProto, val *api.ServiceAttr) (*comm.SrvVal, error) {
	if len(val.RsIps) == 0 {
		return nil, errors.New("real server is empty")
	}
	v := &comm.SrvVal{
		Proto: proto,
		Mode:  comm.ModeNat,
		RPort: uint16(val.Rport),
		RsIps: val.RsIps,
	}
	v.LIP, v.ParentLIP = comm.SplitIP(val.Lip)

	var err error
	if len(pvip) == 0 {
		if v.VDevIdx, err = intf.GetIfIdxByIp(vip); err != nil {
			return nil, errors.Wrapf(err, "get virtual ip(%s) interface index failed", vip)
		}
	} else {
		if v.VDevIdx, err = intf.GetIfIdxByIp(pvip); err != nil {
			return nil, errors.Wrapf(err, "get parent virtual ip(%s) interface index failed", pvip)
		}
	}
	if len(v.ParentLIP) == 0 {
		if v.LDevIdx, err = intf.GetIfIdxByIp(v.LIP); err != nil {
			return nil, errors.Wrapf(err, "get local ip(%s) interface index failed", v.LIP)
		}
	} else {
		if v.LDevIdx, err = intf.GetIfIdxByIp(v.ParentLIP); err != nil {
			return nil, errors.Wrapf(err, "get parent local ip(%s) interface index failed", v.ParentLIP)
		}
	}
	return v, nil
}

func genAPISession(ses []*comm.Session, local bool) []*api.Session {
	se := make([]*api.Session, 0, len(ses))
	if local {
		for _, v := range ses {
			if v.IsLocal {
				se = append(se, v.ToAPI())
			}
		}
	} else {
		for _, v := range ses {
			se = append(se, v.ToAPI())
		}
	}
	return se
}

func genSession(apiSes []*api.Session) []*comm.Session {
	ses := make([]*comm.Session, 0, len(apiSes))
	for _, v := range apiSes {
		se := comm.GetSession()
		se.FromAPI(v)
		ses = append(ses, se)
	}
	return ses
}
