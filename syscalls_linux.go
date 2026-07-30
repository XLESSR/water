package water

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Linux TUN/TAP Interface Flags
// Reference: <linux/if_tun.h>
const (
	cIFFTUN        = 0x0001 // IFF_TUN: Virtual point-to-point IP interface (L3)
	cIFFTAP        = 0x0002 // IFF_TAP: Virtual Ethernet interface (L2)
	cIFFNOCKSUM    = 0x0010 // IFF_NOCKSUM: Disable packet checksum verification for speed
	cIFFMULTIQUEUE = 0x0100 // IFF_MULTI_QUEUE: Enable Linux multi-queue support (v3.8+)
	cIFFNOPI       = 0x1000 // IFF_NO_PI: Do not deliver 4-byte Packet Information header
	cIFFVNETHDR    = 0x4000 // IFF_VNET_HDR: Enable Virtio-net header (GSO/TSO offloading)
	cIFFTUNEXCL    = 0x8000 // IFF_TUN_EXCL: Fail interface creation if name already exists
)

// Linux TUN/TAP Extended IOCTL Commands
// Reference: <linux/if_tun.h>
const (
	cTUNSETVNETHDRSZ = 0x400454d2 // TUNSETVNETHDRSZ: Set Virtio-net header size
	cTUNSETOFFLOAD   = 0x400454d0 // TUNSETOFFLOAD: Configure packet offloading flags (GSO/TSO)
)

// Maximum interface name length excluding null-terminator (IFNAMSIZ = 16)
const maxIFNameLen = 15

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

// validateFd verifies that the provided file descriptor is valid before issuing syscalls.
func validateFd(fd uintptr) error {
	if fd == ^uintptr(0) || int(fd) < 0 {
		return fmt.Errorf("invalid file descriptor: %d", fd)
	}
	return nil
}

// validateIFName performs strict security sanitization on requested network interface names.
func validateIFName(ifName string) error {
	if len(ifName) > maxIFNameLen {
		return fmt.Errorf("interface name %q exceeds maximum allowed length of %d bytes", ifName, maxIFNameLen)
	}
	for i := 0; i < len(ifName); i++ {
		ch := ifName[i]
		if ch == '/' || ch == '\x00' || ch == ' ' || ch == ':' {
			return fmt.Errorf("interface name %q contains illegal character %q", ifName, ch)
		}
	}
	return nil
}

// ioctl is a generic wrapper around Linux `SYS_IOCTL` system call with defensive checks.
func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	if err := validateFd(fd); err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

// setupFd configures a Linux `/dev/net/tun` file descriptor by binding it to an
// interface name, applying interface flags, and setting owner/group/persistence properties.
func setupFd(config Config, fd uintptr) (name string, err error) {
	// Defensive Validation Phase
	if err := validateFd(fd); err != nil {
		return "", fmt.Errorf("setupFd security check failed: %w", err)
	}
	if err := validateIFName(config.Name); err != nil {
		return "", fmt.Errorf("setupFd interface name validation failed: %w", err)
	}

	// Base Flags Configuration
	var flags uint16 = cIFFNOPI

	switch config.DeviceType {
	case TUN:
		flags |= cIFFTUN
	case TAP:
		flags |= cIFFTAP
	default:
		return "", fmt.Errorf("unsupported device type: %v", config.DeviceType)
	}

	// Extended Linux Kernel Features Configuration
	if config.PlatformSpecificParams.MultiQueue {
		flags |= cIFFMULTIQUEUE
	}
	if config.PlatformSpecificParams.VNetHdr {
		flags |= cIFFVNETHDR
	}
	if config.PlatformSpecificParams.NoChecksum {
		flags |= cIFFNOCKSUM
	}
	if config.PlatformSpecificParams.Exclusive {
		flags |= cIFFTUNEXCL
	}

	createdName, err := createInterface(fd, config.Name, flags)
	if err != nil {
		return "", fmt.Errorf("failed to create TUN/TAP interface: %w", err)
	}

	if err := setDeviceOptions(fd, config); err != nil {
		return "", fmt.Errorf("failed to set TUN/TAP device options: %w", err)
	}

	return createdName, nil
}

// createInterface sends the TUNSETIFF ioctl to attach the descriptor to a virtual interface.
// Performs memory zeroing on the input payload to avoid leaking uninitialized stack memory to kernel.
func createInterface(fd uintptr, ifName string, flags uint16) (createdIFName string, err error) {
	var req ifReq

	// Memory Sanitization: Ensure struct memory is zero-initialized
	for i := range req.Name {
		req.Name[i] = 0
	}
	for i := range req.pad {
		req.pad[i] = 0
	}

	req.Flags = flags
	copy(req.Name[:maxIFNameLen], ifName) // Guarantee buffer boundary

	if err := ioctl(fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(&req))); err != nil {
		return "", fmt.Errorf("TUNSETIFF ioctl failed for interface name %q: %w", ifName, err)
	}

	// Safely parse null-terminated string populated by the kernel
	idx := bytes.IndexByte(req.Name[:], 0)
	if idx < 0 {
		idx = maxIFNameLen
	}
	createdName := string(req.Name[:idx])

	if len(createdName) == 0 {
		return "", fmt.Errorf("kernel returned an invalid empty interface name")
	}

	return createdName, nil
}

// setDeviceOptions configures permissions (owner/group), persistence mode,
// Virtio-net header size, and offload capabilities on the TUN/TAP interface.
func setDeviceOptions(fd uintptr, config Config) error {
	// Configure Owner/Group Privileges safely
	if config.Permissions != nil {
		if config.Permissions.Owner < 0 || config.Permissions.Group < 0 {
			return fmt.Errorf("invalid UID (%d) or GID (%d): permissions cannot be negative",
				config.Permissions.Owner, config.Permissions.Group)
		}

		if err := ioctl(fd, syscall.TUNSETOWNER, uintptr(config.Permissions.Owner)); err != nil {
			return fmt.Errorf("TUNSETOWNER failed for UID %d: %w", config.Permissions.Owner, err)
		}

		if err := ioctl(fd, syscall.TUNSETGROUP, uintptr(config.Permissions.Group)); err != nil {
			return fmt.Errorf("TUNSETGROUP failed for GID %d: %w", config.Permissions.Group, err)
		}
	}

	// Configure Custom Virtio-net Header Size (if VNetHdr is enabled and custom size requested)
	if config.PlatformSpecificParams.VNetHdr && config.PlatformSpecificParams.VNetHdrSize > 0 {
		vnetSize := config.PlatformSpecificParams.VNetHdrSize
		if err := ioctl(fd, cTUNSETVNETHDRSZ, uintptr(unsafe.Pointer(&vnetSize))); err != nil {
			return fmt.Errorf("TUNSETVNETHDRSZ failed to set size %d: %w", vnetSize, err)
		}
	}

	// Configure Hardware/Driver Offloading Options (GSO/TSO)
	if config.PlatformSpecificParams.OffloadFlags != 0 {
		offloads := config.PlatformSpecificParams.OffloadFlags
		if err := ioctl(fd, cTUNSETOFFLOAD, uintptr(offloads)); err != nil {
			return fmt.Errorf("TUNSETOFFLOAD failed with flags 0x%x: %w", offloads, err)
		}
	}

	// Configure Persistence Mode
	// Value 1: Interface persists after fd close.
	// Value 0: Interface destroyed immediately upon fd close.
	persistVal := 0
	if config.Persist {
		persistVal = 1
	}

	if err := ioctl(fd, syscall.TUNSETPERSIST, uintptr(persistVal)); err != nil {
		return fmt.Errorf("TUNSETPERSIST failed with mode %d: %w", persistVal, err)
	}

	return nil
}
