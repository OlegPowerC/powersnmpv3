package PowerSNMPv3

import (
	"errors"
	"golang.org/x/sys/windows"
)

func chesockErr(e error) error {
	if errors.Is(e, windows.WSAEMSGSIZE) {
		return errors.New("received datagramm size too big")
	}
	return nil
}
