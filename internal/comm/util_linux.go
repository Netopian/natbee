//go:build !windows
// +build !windows

package comm

import "errors"

func AttachLink(idx, fd int) error {
	/* kernel version need >= 5.7
	l, err := link.AttachXDP(link,XDPOptions{
		Program:   objs.Prog,
		Interface: intfIdx,
		Flags:     link.XDPGenericMode,
	})
	*/
	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return errors.Wrap(err, "get link by index failed")
	}
	return netlink.LinkSetXdpFdWithFlags(link, fd, nl.XDP_FLAGS_SKB_MODE)
}

func DetackLink(idx int) error {
	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return errors.Wrap(err, "get link by index failed")
	}
	return netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE)
}

func AddFilter(idx, fd int) error {
	// declare the Qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: idx,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// add clsact Qdisc
	if err := netlink.QdiscAdd(qdisc); err != nil {
		DelFilter(idx)
		err = netlink.QdiscAdd(qdisc)
		if err != nil {
			return errors.Wrap(err, "cannot add clsact qdisc")
		}
	}

	// create tc filter attributes
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: idx,
		Parent:    netlink.HANDLE_MIN_INGRESS, // direction
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	// declare BPF filter
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           fd,
		Name:         "nb_tc",
		DirectAction: true,
	}

	// add filter
	return netlink.FilterAdd(filter)
}

func DelFilter(idx int) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: idx,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscDel(qdisc); err != nil {
		return errors.Wrap(err, "cannot del clsact qdisc")
	}

	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return errors.Wrap(err, "get link by index failed")
	}

	filters, err := netlink.FilterList(link, 0xFFFFFFF2)
	if err != nil {
		return err
	}

	for _, f := range filters {
		if err := netlink.FilterDel(f); err != nil {
			return err
		}
	}
	return nil
}
