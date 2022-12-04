//go:build windows
// +build windows

package comm

import "errors"

func AttachLink(_, _ int) error {
	return errors.New("attach link is not supported on this os")
}

func DetachLink(_ int) error {
	return errors.New("detach link is not supported on this os")
}

func AddFilter(_, _ int) error {
	return errors.New("add filter is not supported on this os")
}

func DelFilter(_ int) error {
	return errors.New("del  filter is not supported on this os")
}
