package comm

import (
	"encoding/binary"
	"net"
	"sync"
	"unsafe"
)

var (
	sessionPool *sync.Pool
)

func init() {
	sessionPool = &sync.Pool{New: func() interface{} { return new(Session) }}
}

func GetSession() *Session {
	return sessionPool.Get().(*Session)
}

func PutSession(se *Session) {
	sessionPool.Put(se)
}

func IsLittleEndian() bool {
	n := 0x1234
	f := *(*byte)(unsafe.Pointer(&n))
	return (f ^ 0x34) == 0
}

func PutUint16(b []byte, v uint16) {
	if IsLittleEndian() {
		binary.LittleEndian.PutUint16(b, v)
	} else {
		binary.BigEndian.PutUint16(b, v)
	}
}

func GetUint16(b []byte) uint16 {
	if IsLittleEndian() {
		return binary.LittleEndian.Uint16(b)
	} else {
		return binary.BigEndian.Uint16(b)
	}
}

func PutUint32(b []byte, v uint32) {
	if IsLittleEndian() {
		binary.LittleEndian.PutUint32(b, v)
	} else {
		binary.BigEndian.PutUint32(b, v)
	}
}

func GetUint32(b []byte) uint32 {
	if IsLittleEndian() {
		return binary.LittleEndian.Uint32(b)
	} else {
		return binary.BigEndian.Uint32(b)
	}
}

func PutUint64(b []byte, v uint64) {
	if IsLittleEndian() {
		binary.LittleEndian.PutUint64(b, v)
	} else {
		binary.BigEndian.PutUint64(b, v)
	}
}

func GetUint64(b []byte) uint64 {
	if IsLittleEndian() {
		return binary.LittleEndian.Uint64(b)
	} else {
		return binary.BigEndian.Uint64(b)
	}
}

func PutBeAddr(b []byte, proto SockProto, ip net.IP, port uint16) {
	b[1] = byte(proto)
	binary.BigEndian.PutUint16(b[addrPortOffset:], port)
	if v4 := ip.To4(); v4 != nil {
		b[0] = byte(afInet)
		copy(b[addrIpOffset:], v4[:addrIpOffset])
		return
	}
	b[0] = byte(afInet6)
	copy(b[addrIpOffset:], ip.To16())
}

func GetBeAddr(b []byte) (net.IP, uint16, SockProto) {
	port := binary.BigEndian.Uint16(b[addrPortOffset:])
	var ip net.IP
	if b[0] == byte(afInet) {
		ip = net.IPv4(b[addrIpOffset], b[addrIpOffsetAd], b[addrIpOffsetAdd], b[addrIpOffsetAddd])
	} else {
		ip = net.IP(b[addrIpOffset:MapAddrSz]).To16()
	}
	return ip, port, SockProto(b[1])
}

func StrToIp(ipStr string) net.IP {
	var ip net.IP
	if ip = net.ParseIP(ipStr).To4(); ip != nil {
		return ip
	}
	if ip = net.ParseIP(ipStr).To16(); ip != nil {
		return ip
	}
	return nil
}

func StrArrToIpArr(ipStrs []string) ([]net.IP, error) {
	ips := make([]net.IP, 0, len(ipStrs))
	for _, v := range ipStrs {
		ip := StrToIP(v)
		if ip == nil {
			return nil, errors.New(invalid ip string)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func IpArrToStrArr(ips []net.IP) []string {
	ipStrs := make([]string, 0, len(ips))
	for _, v := range ips {
		ipStrs = append(ipStrs, v.String())
	}
	return ipStrs
}

func StrToMac(macStr string) net.HardwareAddr {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return nil
	}
	return mac
}

// return system up time(s)
func GetUptime()(uint64, error) {
	return host.Uptime()
}

func SplitIP(ip string) (string ,string) 
{
	ips := strings.Split(ip, "/")
	if len(ips) > 1 {
		return ips[0], ips[1]
	}
	return ips[0], ""
}

func JoinIP(ip, parentIP string) string {
	if (len(parentIP) == 0) {
		return ip
	}
	return ip + "/" + parentIP
}