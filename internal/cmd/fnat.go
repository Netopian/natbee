package cmd

import (
	"errors"
	"fmt"

	api "github.com/Netopian/natbee/api"

	"github.com/spf13/cobra"
)

var fnatOpts struct {
	attach struct {
		AttachIP string
	}
	detach struct {
		AttachIP string
	}
	add struct {
		VIP   string
		VPort int
		LIP   string
		Proto string
		Rs    []string
		RPort int
	}
	del struct {
		VIP   string
		VPort int
		Proto string
	}
}

func fnatShow() error {
	fmt.Println(`FNatSession
============================================================`)
	resp, err := client.Poll(ctx, &api.PollRequest{Type: api.ServiceType_FNAT})
	if err != nil {
		return err
	}
	for _, s := range resp.FnatSessions {
		fmt.Printf(`P[%s]: C[%s:%d]\tV[%s:%d]
\tL[%s:%d]\tR[%s:%d]
------------------------------------------------------------
`, s.Protocol.String(), s.ClientIp, s.ClientPort, s.VirtualIp, s.VirtualPort,
			s.LocalIp, s.LocalPort, s.RealIp, s.RealPort)
	}
	return nil
}

func verifyFNatOpts(cmdType subCmdType) error {
	switch cmdType {
	case SubCmdShow:
		return nil
	case SubCmdAttach:
		if len(fnatOpts.attach.AttachIP) == 0 {
			return errors.New("invalid attach ip")
		}
	case SubCmdDetach:
		if len(fnatOpts.detach.AttachIP) == 0 {
			return errors.New("invalid attach ip")
		}
	case SubCmdAdd:
		if len(fnatOpts.add.LIP) == 0 {
			return errors.New("invalid local ip")
		}
		if len(fnatOpts.add.Rs) == 0 {
			return errors.New("invalid real server")
		}
		if fnatOpts.add.RPort == 0 {
			fnatOpts.add.RPort = fnatOpts.add.VPort
		} else if fnatOpts.add.RPort < 0x0400 || fnatOpts.add.RPort > 0xFFFF {
			return errors.New("invalid real server port")
		}
		if len(fnatOpts.add.VIP) == 0 {
			return errors.New("invalid virtual ip")
		}
		if fnatOpts.add.VPort < 0x0400 || fnatOpts.add.VPort > 0xFFFF {
			return errors.New("invalid virtual port")
		}
		if fnatOpts.add.Proto != "tcp" && fnatOpts.add.Proto != "udp" {
			return errors.New("invalid protocol")
		}
	case SubCmdDel:
		if len(fnatOpts.del.VIP) == 0 {
			return errors.New("invalid virtual ip")
		}
		if fnatOpts.del.VPort < 0x0400 || fnatOpts.del.VPort > 0xFFFF {
			return errors.New("invalid virtual port")
		}
		if fnatOpts.del.Proto != "tcp" && fnatOpts.del.Proto != "udp" {
			return errors.New("invalid protocol")
		}
	}
	return nil
}

func fnatAttach() error {
	if err := verifyFNatOpts(SubCmdAttach); err != nil {
		return err
	}
	_, err := client.Attach(ctx, &api.AttachRequest{
		Type: api.ServiceType_FNAT,
		Ip:   fnatOpts.attach.AttachIP,
	})
	return err
}

func fnatDetach() error {
	if err := verifyFNatOpts(SubCmdDetach); err != nil {
		return err
	}
	_, err := client.Detach(ctx, &api.AttachRequest{
		Type: api.ServiceType_FNAT,
		Ip:   fnatOpts.attach.AttachIP,
	})
	return err
}

func fnatAdd() error {
	if err := verifyFNatOpts(SubCmdAdd); err != nil {
		return err
	}
	req := &api.AddRequest{
		Type: api.ServiceType_FNAT,
		Key: &api.ServiceKey{
			Ip:   fnatOpts.add.VIP,
			Port: uint32(fnatOpts.add.VPort),
		},
		Val: &api.ServiceAttr{
			LocalIp:       fnatOpts.add.LIP,
			RealPort:      uint32(fnatOpts.add.RPort),
			RealServerIps: fnatOpts.add.Rs,
		},
	}
	if fnatOpts.add.Proto == "tcp" {
		req.Key.Protocol = api.Protocol_TCP
	} else {
		req.Key.Protocol = api.Protocol_UDP
	}
	_, err := client.AddService(ctx, req)
	return err
}

func fnatDel() error {
	if err := verifyFNatOpts(SubCmdDel); err != nil {
		return err
	}
	req := &api.DelRequest{
		Type: api.ServiceType_FNAT,
		Key: &api.ServiceKey{
			Ip:   fnatOpts.add.VIP,
			Port: uint32(fnatOpts.add.VPort),
		},
	}
	if fnatOpts.add.Proto == "tcp" {
		req.Key.Protocol = api.Protocol_TCP
	} else {
		req.Key.Protocol = api.Protocol_UDP
	}
	_, err := client.DelService(ctx, req)
	return err
}

func newFNatCmd() *cobra.Command {
	fnatCmd := &cobra.Command{
		Use: "fnat",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	attachCmd := &cobra.Command{
		Use: "attach",
		Run: func(cmd *cobra.Command, args []string) {
			if err := fnatAttach(); err != nil {
				exitWithError(err)
				cmd.HelpFunc()(cmd, args)
			}
		},
	}
	attachCmd.PersistentFlags().StringVar(&fnatOpts.attach.AttachIP, "aip", "", "attach ip")

	detachCmd := &cobra.Command{
		Use: "detach",
		Run: func(cmd *cobra.Command, args []string) {
			if err := fnatDetach(); err != nil {
				exitWithError(err)
				cmd.HelpFunc()(cmd, args)
			}
		},
	}
	detachCmd.PersistentFlags().StringVar(&fnatOpts.detach.AttachIP, "aip", "", "attach ip")

	addCmd := &cobra.Command{
		Use: "add",
		Run: func(cmd *cobra.Command, args []string) {
			if err := fnatAdd(); err != nil {
				exitWithError(err)
				cmd.HelpFunc()(cmd, args)
			}
		},
	}
	addCmd.PersistentFlags().StringVar(&fnatOpts.add.VIP, "vip", "", "virtual ip, if interface was subport, should take main port ip seperated by '/', such as [subport-ip]/[main-port-ip]")
	addCmd.PersistentFlags().IntVar(&fnatOpts.add.VPort, "vport", 0, "virtual port")
	addCmd.PersistentFlags().StringVar(&fnatOpts.add.LIP, "lip", "", "local ip, if interface was subport, should take main port ip seperated by '/', such as [subport-ip]/[main-port-ip]")
	addCmd.PersistentFlags().StringVar(&fnatOpts.add.Proto, "proto", "", "proto, tcp/udp")
	addCmd.PersistentFlags().StringArrayVar(&fnatOpts.add.Rs, "rs", []string{}, "real servers, multi could config as --rs=x.x.x.x --rs=y.y.y.y")
	addCmd.PersistentFlags().IntVar(&fnatOpts.add.RPort, "rport", 0, "real server port. same as vport while not set")

	delCmd := &cobra.Command{
		Use: "del",
		Run: func(cmd *cobra.Command, args []string) {
			if err := fnatDel(); err != nil {
				exitWithError(err)
				cmd.HelpFunc()(cmd, args)
			}
		},
	}
	delCmd.PersistentFlags().StringVar(&fnatOpts.del.VIP, "vip", "", "virtual ip, if interface was subport, should take main port ip seperated by '/', such as [subport-ip]/[main-port-ip]")
	delCmd.PersistentFlags().IntVar(&fnatOpts.del.VPort, "vport", 0, "virtual port")
	delCmd.PersistentFlags().StringVar(&fnatOpts.del.Proto, "proto", "", "proto, tcp/udp")

	showCmd := &cobra.Command{
		Use: "show",
		Run: func(cmd *cobra.Command, args []string) {
			if err := fnatShow(); err != nil {
				exitWithError(err)
			}
		},
	}

	fnatCmd.AddCommand(addCmd, delCmd, showCmd, attachCmd, detachCmd)
	return fnatCmd
}
