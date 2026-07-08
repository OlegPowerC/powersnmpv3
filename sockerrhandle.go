//go:build !windows

package PowerSNMPv3

import (
	"errors"
	"syscall"
)

func chesockErr(e error) error {
	if errors.Is(e, syscall.EMSGSIZE) {
		return errors.New("received datagramm size too big")
	}
	return nil
}
