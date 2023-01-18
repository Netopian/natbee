package cmd

import (
	"errors"
	"fmt"

	api "github.com/Netopian/natbee/api"

	"github.com/spf13/cobra"
)

var natOpts struct {
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

func natShow() error {
	fmt.Println(`NatSession
============================================================`)
	resp, err := client.Poll(ctx, &api.PollRequest{Type: api.ServiceType_NAT})
	if err != nil {
		return err
	}
	for _, s := range resp.NatSessions {
		fmt.Printf(`P[%s]: C[%s:%d]\tV[%s:%d]
\tR[%s:%d]
------------------------------------------------------------
`, s.Protocol.String(), s.ClientIp, s.ClientPort, s.VirtualIp, s.VirtualPort, s.RealIp, s.RealPort)
	}
	return nil
}

func verifyNatOpts(cmdType subCmdType) error {
	switch cmdType {
	case SubCmdShow:
		return nil
	case SubCmdAttach:
		if len(natOpts.attach.AttachIP) == 0 {
			return errors.New("invalid attach ip")
		}
	case SubCmdDetach:
		if len(natOpts.detach.AttachIP) == 0 {
			return errors.New("invalid attach ip")
		}
	case SubCmdAdd:
		if len(natOpts.add.LIP) == 0 {
			return errors.New("invalid local ip")
		}
		if len(natOpts.add.Rs) == 0 {
			return errors.New("invalid real server")
		}
		if natOpts.add.RPort == 0 {
			natOpts.add.RPort = natOpts.add.VPort
		} else if natOpts.add.RPort < 0x0400 || natOpts.add.RPort > 0xFFFF {
			return errors.New("invalid real server port")
		}
		if len(natOpts.add.VIP) == 0 {
			return errors.New("invalid virtual ip")
		}
		if natOpts.add.VPort < 0x0400 || natOpts.add.VPort > 0xFFFF {
			return errors.New("invalid virtual port")
		}
		if natOpts.add.Proto != "tcp" && natOpts.add.Proto != "udp" {
			return errors.New("invalid protocol")
		}
	case SubCmdDel:
		if len(natOpts.del.VIP) == 0 {
			return errors.New("invalid virtual ip")
		}
		if natOpts.del.VPort < 0x0400 || natOpts.del.VPort > 0xFFFF {
			return errors.New("invalid virtual port")
		}
		if natOpts.del.Proto != "tcp" && natOpts.del.Proto != "udp" {
			return errors.New("invalid protocol")
		}
	}
	return nil
}

func natAttach() error {
	if err := verifyNatOpts(SubCmdAttach); err != nil {
		return err
	}
	_, err := client.Attach(ctx, &api.AttachRequest{
		Type: api.ServiceType_NAT,
		Ip:   natOpts.attach.AttachIP,
	})
	return err
}

func natDetach() error {
	if err := verifyNatOpts(SubCmdDetach); err != nil {
		return err
	}
	_, err := client.Detach(ctx, &api.AttachRequest{
		Type: api.ServiceType_NAT,
		Ip:   natOpts.attach.AttachIP,
	})
	return err
}

func natAdd() error {
	if err := verifyNatOpts(SubCmdAdd); err != nil {
		return err
	}
	req := &api.AddRequest{
		Type: api.ServiceType_NAT,
		Key: &api.ServiceKey{
			Ip:   natOpts.add.VIP,
			Port: uint32(natOpts.add.VPort),
		},
		Val: &api.ServiceAttr{
			LocalIp:       natOpts.add.LIP,
			RealPort:      uint32(natOpts.add.RPort),
			RealServerIps: natOpts.add.Rs,
		},
	}
	if natOpts.add.Proto == "tcp" {
		req.Key.Protocol = api.Protocol_TCP
	} else {
		req.Key.Protocol = api.Protocol_UDP
	}
	_, err := client.AddService(ctx, req)
	return err
}

func natDel() error {
	if err := verifyNatOpts(SubCmdDel); err != nil {
		return err
	}
	req := &api.DelRequest{
		Type: api.ServiceType_NAT,
		Key: &api.ServiceKey{
			Ip:   natOpts.add.VIP,
			Port: uint32(natOpts.add.VPort),
		},
	}
	if natOpts.add.Proto == "tcp" {
		req.Key.Protocol = api.Protocol_TCP
	} else {
		req.Key.Protocol = api.Protocol_UDP
	}
	_, err := client.DelService(ctx, req)
	return err
}

func newNatCmd() *cobra.Command {
	natCmd := &cobra.Command{
		Use: "nat",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	attachCmd := &cobra.Command{
		Use: "attach",
		Run: func(cmd *cobra.Command, args []string) {
			if err := natAttach(); err != nil {
				exitWithError(err)
				cmd.HelpFunc()(cmd, args)
			}
		},
	}
	attachCmd.PersistentFlags().StringVar(&natOpts.attach.AttachIP, "aip", "", "attach ip")

	detachCmd := &cobra.Command{
		Use: "detach",
		Run: func(cmd *cobra.Command, args []string) {
			if err := natDetach(); err != nil {
				exitWithError(err)
				cmd.HelpFunc()(cmd, args)
			}
		},
	}
	detachCmd.PersistentFlags().StringVar(&natOpts.detach.AttachIP, "aip", "", "attach ip")

	addCmd := &cobra.Command{
		Use: "add",
		Run: func(cmd *cobra.Command, args []string) {
			if err := natAdd(); err != nil {
				exitWithError(err)
				cmd.HelpFunc()(cmd, args)
			}
		},
	}
	addCmd.PersistentFlags().StringVar(&natOpts.add.VIP, "vip", "", "virtual ip, if interface was subport, should take main port ip seperated by '/', such as [subport-ip]/[main-port-ip]")
	addCmd.PersistentFlags().IntVar(&natOpts.add.VPort, "vport", 0, "virtual port")
	addCmd.PersistentFlags().StringVar(&natOpts.add.LIP, "lip", "", "local ip, if interface was subport, should take main port ip seperated by '/', such as [subport-ip]/[main-port-ip]")
	addCmd.PersistentFlags().StringVar(&natOpts.add.Proto, "proto", "", "proto, tcp/udp")
	addCmd.PersistentFlags().StringArrayVar(&natOpts.add.Rs, "rs", []string{}, "real servers, multi could config as --rs=x.x.x.x --rs=y.y.y.y")
	addCmd.PersistentFlags().IntVar(&natOpts.add.RPort, "rport", 0, "real server port. same as vport while not set")

	delCmd := &cobra.Command{
		Use: "del",
		Run: func(cmd *cobra.Command, args []string) {
			if err := natDel(); err != nil {
				exitWithError(err)
				cmd.HelpFunc()(cmd, args)
			}
		},
	}
	delCmd.PersistentFlags().StringVar(&natOpts.del.VIP, "vip", "", "virtual ip, if interface was subport, should take main port ip seperated by '/', such as [subport-ip]/[main-port-ip]")
	delCmd.PersistentFlags().IntVar(&natOpts.del.VPort, "vport", 0, "virtual port")
	delCmd.PersistentFlags().StringVar(&natOpts.del.Proto, "proto", "", "proto, tcp/udp")

	showCmd := &cobra.Command{
		Use: "show",
		Run: func(cmd *cobra.Command, args []string) {
			if err := natShow(); err != nil {
				exitWithError(err)
			}
		},
	}

	natCmd.AddCommand(addCmd, delCmd, showCmd, attachCmd, detachCmd)
	return natCmd
}
