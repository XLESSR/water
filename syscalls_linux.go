package water

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"
)

// Linux TUN/TAP Interface Flags
// Reference: <linux/if_tun.h>
const (
	cIFFTUN        = 0x0001 // IFF_TUN: Virtual point-to-point IP interface (L3)
	cIFFTAP        = 0x0002 // IFF_TAP: Virtual Ethernet interface (L2)
	cIFFNOPI       = 0x1000 // IFF_NO_PI: Do not deliver 4-byte Packet Information header
	cIFFMULTIQUEUE = 0x0100 // IFF_MULTI_QUEUE: Enable Linux multi-queue support (v3.8+)
)

// ifReq mirrors the C structure `struct ifreq` from <linux/if.h>.
//
// Layout Memory Structure:
// - Name: [16]byte (IFNAMSIZ = 16 bytes)
// - Flags: uint16 (ifr_flags = 2 bytes)
// - Pad: [22]byte (Padded to match the standard 40-byte size of `struct ifreq` union)
type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

// ioctl is a generic wrapper around Linux `SYS_IOCTL` system call.
func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

// setupFd configures a Linux `/dev/net/tun` file descriptor by binding it to an
// interface name, applying interface flags, and setting owner/group/persistence properties.
func setupFd(config Config, fd uintptr) (name string, err error) {
	// By default, request IFF_NO_PI so raw IP/Ethernet packets are read without extra kernel headers.
	var flags uint16 = cIFFNOPI

	if config.DeviceType == TUN {
		flags |= cIFFTUN
	} else {
		flags |= cIFFTAP
	}

	if config.PlatformSpecificParams.MultiQueue {
		flags |= cIFFMULTIQUEUE
	}

	createdName, err := createInterface(fd, config.Name, flags)
	if err != nil {
		return "", err
	}

	if err := setDeviceOptions(fd, config); err != nil {
		return "", err
	}

	return createdName, nil
}

// createInterface sends the TUNSETIFF ioctl to attach the descriptor to a virtual interface.
// If ifName is empty (e.g. ""), the Linux kernel will automatically allocate the next
// available interface index (e.g. "tun0" or "tap0").
func createInterface(fd uintptr, ifName string, flags uint16) (createdIFName string, err error) {
	var req ifReq
	req.Flags = flags
	copy(req.Name[:], ifName)

	if err := ioctl(fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(&req))); err != nil {
		return "", err
	}

	// Parse null-terminated string populated by the kernel in req.Name
	if i := bytes.IndexByte(req.Name[:], 0); i >= 0 {
		return string(req.Name[:i]), nil
	}
	return string(req.Name[:]), nil
}

// setDeviceOptions configures permissions (owner/group) and persistence mode on the TUN/TAP interface.
func setDeviceOptions(fd uintptr, config Config) error {
	if config.Permissions != nil {
		// Set ownership (UID/GID) allowing unprivileged users to access the interface
		if err := ioctl(fd, syscall.TUNSETOWNER, uintptr(config.Permissions.Owner)); err != nil {
			return err
		}
		if err := ioctl(fd, syscall.TUNSETGROUP, uintptr(config.Permissions.Group)); err != nil {
			return err
		}
	}

	// TUNSETPERSIST controls interface lifespan.
	// value = 1: Keep interface alive even when file descriptor is closed.
	// value = 0: Destroy interface automatically when descriptor is closed.
	persistVal := 0
	if config.Persist {
		persistVal = 1
	}

	return ioctl(fd, syscall.TUNSETPERSIST, uintptr(persistVal))
}
