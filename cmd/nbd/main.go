package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/Netopian/natbee/pkg/balancer"
	"github.com/Netopian/natbee/pkg/config"
	"github.com/Netopian/natbee/pkg/server"

	flags "github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)

	var opts struct {
		GrpcPort       int    `short:"p" long:"api-port" description:"specify the port that natbee listen on" default:"8081"`
		ConfigFilePath string `short:"c" long:"config" description:"specify the configuration file path" default:"nbd.yaml"`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	conf, err := config.ReadConfigfile(opts.ConfigFilePath)
	if err != nil {
		log.Errorf("read configuration file failed: %v", err)
		os.Exit(1)
	}
	b, err := balancer.NewBalancer(conf)
	if err != nil {
		log.Errorf("create load balancer failed: %v", err)
		os.Exit(1)
	}
	defer b.Release()

	s := server.NewAPIServer(grpc.NewServer(), b, conf, uint16(opts.GrpcPort))
	if err = s.Serve(); err != nil {
		log.Errorf("natbee serve failed: %v", err)
		os.Exit(1)
	}
	log.Info(`
	`)
	<-sigCh
}
