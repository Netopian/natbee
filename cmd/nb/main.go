package main

import (
	"natbee/internal/cmd"

	"google.golang.org/grpc"
)

func main() {
	grpc.EnableTracing = false
	cmd.NewRootCmd().Execute()
}
