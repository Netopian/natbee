package main

import (
	"github.com/Netopian/natbee/internal/cmd"

	"google.golang.org/grpc"
)

func main() {
	grpc.EnableTracing = false
	cmd.NewRootCmd().Execute()
}
