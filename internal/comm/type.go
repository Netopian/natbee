package comm

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

	api "github.com/Netopian/natbee/api"
)

type BpfMode = uint32

const (
	NodeInvalid BpfMode = 0
	ModeNat     BpfMode = 0x1
	ModeFNat    BpfMode = 0x2
)

type AfType = byte

const (
	afInet  AfType = 2
	afInet6 AfType = 10
)

type SockProto byte

const (
	protoTCP SockProto = 6
	protoUDP SockProto = 17
)

const (
	MapAddrSz           int           = 20
	MapRealServerSz     int           = 24
	MapConnKeySz        int           = 40
	MapConnValSz        int           = 56
	TickerTime          time.Duration = 2 * time.Second
	NsCnt               uint64        = 1000000000
	DefaultConnTimeout  uint32        = 5
	DefailtApiPort      int           = 8081
	srvKeySz            int           = 20
	srvValSz            int           = 36
	srvRsPortOffset     int           = 22
	srvRsIpCntOffset    int           = 24
	srvVirtualIdxOffset int           = 28
	srvLocalIdxOffset   int           = 32
	connIdxOffset       int           = 40
	connLocalOffset     int           = 44
	connLocalPortOffset int           = 45
	connPositiveOffset  int           = 46
	connTsOffset        int           = 48
	addrPortOffset      int           = 2
	addrIpOffset        int           = 4
	addrIpOffsetAd      int           = 5
	addrIpOffsetAdd     int           = 6
	addrIpOffsetAddd    int           = 7
)

func GetAddrFamily(ipStr string) (AfType, error) {
	var ip net.IP
	if ip = net.ParseIP(ipStr).To4(); ip != nil {
		return afInet, nil
	}
	if ip = net.ParseIP(ipStr).To16(); ip != nil {
		return afInet6, nil
	}
	return afInet, errors.New("invalid address family")
}

var (
	sockProtoName = map[SockProto]string{
		protoTCP: "tcp",
		protoUDP: "udp",
	}
	sockProtoValue = map[string]SockProto{
		"tcp": protoTCP,
		"udp": protoUDP,
	}
)

func (p SockProto) String() string {
	if s, ok := sockProtoName[p]; ok {
		return s
	}
	return ""
}

func (p SockProto) Valid() bool {
	_, ok := sockProtoName[p]
	return ok
}

func SockProtoValue(v string) (SockProto, error) {
	s, ok := sockProtoValue[v]
	if ok {
		return s, nil
	}
	return protoTCP, errors.New("invalid proto")
}

type Service interface {
	Add(*SrvKey, *SrvVal) error
	Del(*SrvKey) error
	Attach(int) error
	Detach(int) error
	PollSession() []*Session
	PushSession([]*Session)
	Release()
}

type SrvKey struct {
	IP       string
	ParentIP string
	Port     uint16
	Proto    SockProto
}

func (k *SrvKey) Marshal() ([]byte, error) {
	b := make([]byte, srvKeySz)
	ip := ConvertToIP(k.IP)
	if ip == nil {
		return nil, errors.New("invalid ip")
	}
	PutBeAddr(b, k.Proto, ip, k.Port)
	return b, nil
}

type SrvVal struct {
	LocalIP       string
	ParentLocalIP string
	Proto         SockProto
	Mode          BpfMode
	Strategy      byte
	RealPort      uint16
	RealServerIPs []string
	VirtualIfIdx  int
	LocalIfIdx    int
	Timeout       uint32
}

func (v *SrvVal) Marshal() ([]byte, error) {
	b := make([]byte, srvValSz)
	ip := ConvertToIP(v.LocalIP)
	if ip == nil {
		return nil, errors.New("invalid ip")
	}
	PutBeAddr(b, v.Proto, ip, 0)
	b[MapAddrSz] = v.Strategy
	binary.BigEndian.PutUint16(b[srvRsPortOffset:], v.RealPort)
	PutUint16(b[srvRsIpCntOffset:], uint16(len(v.RealServerIPs)))
	PutUint32(b[srvVirtualIdxOffset:], uint32(v.VirtualIfIdx))
	PutUint32(b[srvLocalIdxOffset:], uint32(v.LocalIfIdx))
	return b, nil
}

type ConnKey struct {
	Af      AfType
	Proto   SockProto
	RxSIP   string
	RxSPort uint16
	RxDIP   string
	RxDPort uint16
}

func (k *ConnKey) Marshal() ([]byte, error) {
	b := make([]byte, MapConnKeySz)
	ip := ConvertToIP(k.RxSIP)
	if ip == nil {
		return nil, errors.New("invalid rxsip")
	}
	PutBeAddr(b[:MapAddrSz], k.Proto, ip, k.RxSPort)
	if ip = ConvertToIP(k.RxDIP); ip == nil {
		return nil, errors.New("invalid rxdip")
	}
	PutBeAddr(b[MapAddrSz:], k.Proto, ip, k.RxDPort)
	return b, nil
}

func (k *ConnKey) Unmarshal(b []byte) error {
	var ip net.IP
	ip, k.RxSPort, k.Proto = GetBeAddr(b[:MapAddrSz])
	if ip.To4() != nil {
		k.Af = afInet
	} else if ip.To16() != nil {
		k.Af = afInet6
	} else {
		return errors.New("invalid rxsip")
	}
	k.RxSIP = ip.String()
	ip, k.RxDPort, _ = GetBeAddr(b[MapAddrSz:])
	if ip.To4() == nil && ip.To16() == nil {
		return errors.New("invalid rxdip")
	}
	k.RxDIP = ip.String()
	return nil
}

type ConnVal struct {
	TxSrcIP     string
	TxSrcPort   uint16
	TxDstIP     string
	TxDstPort   uint16
	IfIdx       uint32
	Proto       SockProto
	Ts          uint64
	IsLocal     bool
	IsLocalPort bool
	IsPositive  bool
}

func (v *ConnVal) Marshal() ([]byte, error) {
	b := make([]byte, MapConnValSz)
	ip := ConvertToIP(v.TxSrcIP)
	if ip == nil {
		return nil, errors.New("invalid txsip")
	}
	PutBeAddr(b[:MapAddrSz], v.Proto, ip, v.TxSrcPort)
	if ip = ConvertToIP(v.TxDstIP); ip == nil {
		return nil, errors.New("invalid txdip")
	}
	PutBeAddr(b[MapAddrSz:], v.Proto, ip, v.TxDstPort)
	PutUint32(b[connIdxOffset:], v.IfIdx)
	if v.IsLocal {
		b[connLocalOffset] = 1
	}
	if v.IsLocalPort {
		b[connLocalPortOffset] = 1
	}
	if v.IsPositive {
		b[connPositiveOffset] = 1
	}
	PutUint64(b[connTsOffset:], v.Ts)
	return b, nil
}

func (v *ConnVal) Unmarshal(b []byte) error {
	var ip net.IP
	ip, v.TxSrcPort, v.Proto = GetBeAddr(b[:MapAddrSz])
	if ip.To4() == nil && ip.To16() == nil {
		return errors.New("invalid txsip")
	}
	v.TxSrcIP = ip.String()
	ip, v.TxDstPort, _ = GetBeAddr(b[MapAddrSz:])
	if ip.To4() == nil && ip.To16() == nil {
		return errors.New("invalid txdip")
	}
	v.TxDstIP = ip.String()
	v.IfIdx = GetUint32(b[connIdxOffset:])
	v.IsLocal = b[connLocalOffset] > 0
	v.IsLocalPort = b[connLocalPortOffset] > 0
	v.IsPositive = b[connPositiveOffset] > 0
	v.Ts = GetUint64(b[connTsOffset:])
	return nil
}

type Session struct {
	CIP     string
	CPort   uint16
	VIP     string
	VPort   uint16
	LIP     string
	LPort   uint16
	RIP     string
	RPort   uint16
	Proto   SockProto
	IsLocal bool
}

func (s *Session) FromConn(k *ConnKey, v *ConnVal) {
	s.CIP = k.RxSIP
	s.CPort = k.RxSPort
	s.VIP = k.RxDIP
	s.VPort = k.RxDPort
	s.LIP = v.TxSrcIP
	s.LPort = v.TxSrcPort
	s.RIP = v.TxDstIP
	s.RPort = v.TxDstPort
	s.Proto = k.Proto
	s.IsLocal = v.IsLocal
}

func (s *Session) FromAPI(se *api.Session) {
	s.CIP = se.ClientIp
	s.CPort = uint16(se.ClientPort)
	s.VIP = se.VirtualIp
	s.VPort = uint16(se.VirtualPort)
	s.LIP = se.LocalIp
	s.LPort = uint16(se.LocalPort)
	s.RIP = se.RealIp
	s.RPort = uint16(se.RealPort)
	s.Proto = SockProto(se.Protocol)
	s.IsLocal = false
}

func (s *Session) ToConn(af AfType, virtualIfIdx, localIfIdx uint32, ts uint64) ([]ConnKey, []ConnVal) {
	ks := make([]ConnKey, 2)
	vs := make([]ConnVal, 2)
	ks[0] = ConnKey{af, s.Proto, s.CIP, s.CPort, s.VIP, s.VPort}
	vs[0] = ConnVal{s.LIP, s.LPort, s.RIP, s.RPort, localIfIdx, s.Proto, ts, false, false, true}
	ks[1] = ConnKey{af, s.Proto, s.RIP, s.RPort, s.LIP, s.LPort}
	vs[1] = ConnVal{s.VIP, s.VPort, s.CIP, s.CPort, virtualIfIdx, s.Proto, ts, false, false, false}
	return ks, vs
}

func (s *Session) ToAPI() *api.Session {
	return &api.Session{
		ClientIp:    s.CIP,
		ClientPort:  uint32(s.CPort),
		VirtualIp:   s.VIP,
		VirtualPort: uint32(s.VPort),
		LocalIp:     s.LIP,
		LocalPort:   uint32(s.LPort),
		RealIp:      s.RIP,
		RealPort:    uint32(s.RPort),
		Protocol:    api.Protocol(s.Proto),
	}
}
