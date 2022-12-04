package netraw

import (
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snaplen int32 = 65536
	macSz   uint8 = 6
	v4Sz    uint8 = 4
	v6Sz    uint8 = 16
)

func Arp(src, dst net.IP) {
	intf := getIface(src)
	if intf == nil {
		log.Errorf("get interface(%v) failed", src)
		return
	}
	handle, err := pcap.OpenLive(intf.Name, snaplen, true, pcap.BlockForever)
	if err != nil {
		log.Errorf("pcap open failed: %v", err)
		return
	}
	defer handle.Close()

	var ethType layers.EthernetType
	var addrSz uint8
	var srcIP, dstIP net.IP
	if srcIP, dstIP = src.To4(), dst.To4(); srcIP != nil && dstIP != nil {
		ethType = layers.EthernetTypeIPv4
		addrSz = v4Sz
	} else if srcIP, dstIP = src.To16(), dst.To16(); srcIP != nil && dstIP != nil {
		ethType = layers.EthernetTypeIPv6
		addrSz = v6Sz
	} else {
		log.Error("invalid addr")
		return
	}

	eth := &layers.Ethernet{
		SrcMAC:       intf.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          ethType,
		HwAddressSize:     macSz,
		ProtAddressSize:   addrSz,
		Operation:         uint16(1),
		SourceHwAddress:   intf.HardwareAddr,
		SourceProtAddress: srcIP,
		DstHwAddress:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstProtAddress:    dstIP,
	}

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, eth, a)
	arpMsg := buffer.Bytes()

	if err = handle.WritePacketData(arpMsg); err != nil {
		log.Errorf("send arp failed: %v", err)
	}
}

func getIface(ip net.IP) *net.Interface {
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) <= 1 {
		return nil
	}

	for _, v := range ifs {
		addrs, err := v.Addrs()
		if err != nil {
			continue
		}
		intf := v
		for _, addr := range addrs {
			if addr.(*net.IPNet).IP.Equal(ip) {
				return &intf
			}
		}
	}
	return nil
}
