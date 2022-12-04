package intf

import (
	"fmt"
	"natbee/internal/comm"
	"net"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	ipIfs sync.Map
)

func RefreshInterfaces() error {
	return updateIfs()
}

func GetIfIdxByIp(ipStr string) (int, error) {
	ip := comm.StrToIp(ipStr)
	if ip == nil {
		return 0, errors.New("invalid ip")
	}
	if v, ok := ipIfs.Load(ip.String()); ok {
		return v.(*net.Interface).Index, nil
	}
	return 0, fmt.Errorf("not found interface of [%s]", ipStr)
}

func GetIfNameByIp(ipStr string) (string, error) {
	ip := comm.StrToIp(ipStr)
	if ip == nil {
		return "", errors.New("invalid ip")
	}
	if v, ok := ipIfs.Load(ip.String()); ok {
		return v.(*net.Interface).Name, nil
	}
	return "", fmt.Errorf("not found interface of [%s]", ipStr)
}

func updateIfs() error {
	ifs, err := net.Interfaces()
	if err != nil {
		return errors.Wrap(err, "get interfaces failed")
	}
	if len(ifs) <= 1 {
		return errors.New("interface none")
	}

	for _, v := range ifs {
		addrs, err := v.Addrs()
		if err != nil {
			log.Errorf("get interface[%s], address, failed: %v", v.Name, err)
			continue
		}
		intf := v
		for _, addr := range addrs {
			if ip := addr.(*net.IPNet).IP.To4(); ip != nil {
				ipIfs.Store(ip.String(), &intf)
			}
			if ip := addr.(*net.IPNet).IP.To16(); ip != nil {
				ipIfs.Store(ip.String(), &intf)
			}
		}
	}
	return nil
}
