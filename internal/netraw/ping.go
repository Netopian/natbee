package netraw

import (
	"net"

	"github.com/go-ping/ping"
	log "github.com/sirupsen/logrus"
)

func Ping(dst net.IP) {
	pinger, err := ping.NewPinger(dst.String())
	if err != nil {
		log.Errorf("create pinger failed: %v", err)
		return
	}
	pinger.SetPrivileged(true)
	pinger.Count = 1
	if err = pinger.run(); err != nil {
		log.Errorf("ping %s failed: %v", dst.String(), err)
	}
}
