package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	api "github.com/Netopian/natbee/api"
	"github.com/Netopian/natbee/internal/comm"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var (
	cfgFile string
	doOnce  sync.Once
	client  api.NatBeeApiClient
	ctx     context.Context
)

var globalOpts struct {
	Port int
}

type subCmdType int

const (
	SubCmdAdd    subCmdType = 1
	SubCmdDel    subCmdType = 2
	SubCmdShow   subCmdType = 3
	SubCmdAttach subCmdType = 4
	SubCmdDetach subCmdType = 5
)

func NewRootCmd() *cobra.Command {
	cobra.EnablePrefixMatching = true
	var cancel context.CancelFunc
	rootCmd := &cobra.Command{
		Use: "nb",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			ctx = context.Background()
			if client, cancel, err = newClient(ctx); err != nil {
				cancel()
				exitWithError(err)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(`
			`)
			cmd.HelpFunc()(cmd, args)
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if cancel != nil {
				cancel()
			}
		},
	}

	rootCmd.PersistentFlags().IntVarP(&globalOpts.Port, "port", "p", comm.DefailtApiPort, "natbee deamon service api port")
	rootCmd.AddCommand([]*cobra.Command{newNatCmd(), newFNatCmd(), newSaveCmd()}...)
	return rootCmd
}

func newClient(ctx context.Context) (api.NatBeeApiClient, context.CancelFunc, error) {
	grpcOpts := []grpc.DialOption{grpc.WithBlock(), grpc.WithInsecure()}
	cc, cancel := context.WithTimeout(ctx, time.Second)
	conn, err := grpc.DialContext(cc, "localhost:"+strconv.Itoa(globalOpts.Port), grpcOpts...)
	if err != nil {
		return nil, cancel, err
	}
	return api.NewNatBeeApiClient(conn), cancel, nil
}

func exitWithError(err error) {
	fmt.Println(err)
	os.Exit(1)
}
