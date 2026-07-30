package water

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// macOS Control and Socket Constants
// Reference: xnu /bsd/sys/sys_domain.h, /bsd/sys/kern_control.h
const (
	appleUTUNCtl     = "com.apple.net.utun_control"
	sysprotoControl  = 2 // SYSPROTO_CONTROL: Kernel Control Protocol
	afSysControl     = 2 // AF_SYS_CONTROL: Address family subtype for Kernel Control
	utunOptIfName    = 2 // UTUN_OPT_IFNAME: Socket option to query the allocated interface name
)

/*
 * C Macro Definitions Breakdown for IOC calculations:
 * IOCPARM_MASK = 0x1fff (13 bits length parameter)
 * IOC_OUT      = 0x40000000 (copy out parameters)
 * IOC_IN       = 0x80000000 (copy in parameters)
 * IOC_INOUT    = IOC_IN | IOC_OUT
 * _IOC(inout, group, num, len) = (inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (num))
 * _IOWR(g, n, t)               = _IOC(IOC_INOUT, (g), (n), sizeof(t))
 *
 * appleCTLIOCGINFO: _IOWR('N', 3, struct ctl_info)
 *   sizeof(struct ctl_info) = 100
 */
const appleCTLIOCGINFO = (0x40000000 | 0x80000000) | ((100 & 0x1fff) << 16) | uint32(byte('N'))<<8 | 3

/*
 * appleTUNSIFMODE: _IOW('t', 94, int)
 *   sizeof(int) = 4
 */
const appleTUNSIFMODE = (0x80000000) | ((4 & 0x1fff) << 16) | uint32(byte('t'))<<8 | 94

// sockaddrCtl represents the kernel control address structure required by macOS to connect to control sockets.
// Reference: C structure `sockaddr_ctl` defined in /bsd/sys/kern_control.h
type sockaddrCtl struct {
	scLen      uint8     // Length of structure (32 bytes)
	scFamily   uint8     // AF_SYSTEM
	ssSysaddr  uint16    // AF_SYS_CONTROL
	scID       uint32    // Controller unique identifier (assigned dynamically via CTLIOCGINFO)
	scUnit     uint32    // Unit number (1-based index, e.g., 1 for utun0; 0 lets kernel auto-assign)
	scReserved [5]uint32 // Reserved for future extension
}

// Dynamically retrieve struct size using unsafe.Sizeof
var sockaddrCtlSize = unsafe.Sizeof(sockaddrCtl{})

// openDev opens a network interface based on the configured driver.
func openDev(config Config) (*Interface, error) {
	switch config.Driver {
	case MacOSDriverSystem:
		return openDevSystem(config)
	case MacOSDriverTunTapOSX:
		return openDevTunTapOSX(config)
	default:
		return nil, errors.New("unrecognized driver")
	}
}

// openDevSystem creates a TUN device using Apple's native system utun control socket.
func openDevSystem(config Config) (*Interface, error) {
	if config.DeviceType != TUN {
		return nil, errors.New("only TUN device type is supported by SystemDriver; use TunTapOSXDriver for TAP")
	}

	// Parse custom utun interface index if requested (e.g., "utun2" -> unit 3).
	// Unit number is 1-indexed (scUnit = unit + 1). Unit 0 allows auto-assignment by kernel.
	ifIndex := -1
	if config.Name != "" {
		const utunPrefix = "utun"
		if !strings.HasPrefix(config.Name, utunPrefix) {
			return nil, fmt.Errorf("interface name must match pattern utun[0-9]+")
		}
		var err error
		ifIndex, err = strconv.Atoi(config.Name[len(utunPrefix):])
		if err != nil || ifIndex < 0 || ifIndex > math.MaxUint32-1 {
			return nil, fmt.Errorf("interface name must match pattern utun[0-9]+")
		}
	}

	// Open kernel control socket: socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
	fd, err := syscall.Socket(syscall.AF_SYSTEM, syscall.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("error in syscall.Socket: %w", err)
	}

	// Retrieve control ID for the "com.apple.net.utun_control" module
	ctlInfo := &struct {
		ctlID   uint32
		ctlName [96]byte
	}{}
	copy(ctlInfo.ctlName[:], appleUTUNCtl)

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(appleCTLIOCGINFO), uintptr(unsafe.Pointer(ctlInfo))); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("error resolving utun control ID via ioctl CTLIOCGINFO: %w", errno)
	}

	// Connect to the control socket to instantiate the interface
	addr := sockaddrCtl{
		scLen:     uint8(sockaddrCtlSize),
		scFamily:  syscall.AF_SYSTEM,
		ssSysaddr: afSysControl,
		scID:      ctlInfo.ctlID,
		scUnit:    uint32(ifIndex + 1), // 0: Auto-assign, >0: Specified utun unit
	}

	if _, _, errno := syscall.RawSyscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr)), uintptr(sockaddrCtlSize)); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("error connecting to kernel control socket: %w", errno)
	}

	// Retrieve actual assigned interface name (e.g., "utun0")
	var ifName [16]byte
	ifNameSize := uintptr(len(ifName))
	if _, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(sysprotoControl),
		uintptr(utunOptIfName),
		uintptr(unsafe.Pointer(&ifName[0])),
		uintptr(unsafe.Pointer(&ifNameSize)),
		0,
	); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("error getting interface name via getsockopt: %w", errno)
	}

	// Parse C string by stripping null bytes
	assignedName := string(bytes.TrimRight(ifName[:ifNameSize], "\x00"))

	if err = setNonBlock(fd); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("error setting non-blocking mode: %w", err)
	}

	return &Interface{
		isTAP: false,
		name:  assignedName,
		ReadWriteCloser: &tunReadCloser{
			f: os.NewFile(uintptr(fd), assignedName),
		},
	}, nil
}

// openDevTunTapOSX opens a TUN/TAP device assuming the third-party tuntaposx kernel extension is installed.
func openDevTunTapOSX(config Config) (*Interface, error) {
	if config.DeviceType == TAP && !strings.HasPrefix(config.Name, "tap") {
		return nil, errors.New("device name must start with 'tap' when creating a TAP device")
	}
	if config.DeviceType == TUN && !strings.HasPrefix(config.Name, "tun") {
		return nil, errors.New("device name must start with 'tun' when creating a TUN device")
	}
	if config.DeviceType != TAP && config.DeviceType != TUN {
		return nil, errors.New("unsupported DeviceType")
	}
	if len(config.Name) >= 15 {
		return nil, errors.New("device name is too long")
	}

	fd, err := syscall.Open("/dev/"+config.Name, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	// Note: We do not call setNonBlock on fd here because it breaks tuntaposx.
	// See https://sourceforge.net/p/tuntaposx/bugs/6/

	// Create temporary socket for interface setup (SIOCGIFFLAGS/SIOCSIFFLAGS ioctls)
	socketFD, err := syscall.Socket(syscall.AF_SYSTEM, syscall.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("error creating control socket: %w", err)
	}
	defer syscall.Close(socketFD)

	var ifReq struct {
		ifName    [16]byte
		ifruFlags int16
		pad       [16]byte
	}
	copy(ifReq.ifName[:], config.Name)

	// Fetch interface flags
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(socketFD), uintptr(syscall.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifReq))); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("error getting interface flags via ioctl: %w", errno)
	}

	// Set interface UP and RUNNING
	ifReq.ifruFlags |= syscall.IFF_RUNNING | syscall.IFF_UP
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(socketFD), uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifReq))); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("error setting interface flags via ioctl: %w", errno)
	}

	return &Interface{
		isTAP:           config.DeviceType == TAP,
		ReadWriteCloser: os.NewFile(uintptr(fd), config.Name),
		name:            config.Name,
	}, nil
}

// tunReadCloser wraps an underlying ReadWriteCloser to handle macOS `utun`'s 4-byte
// Packet Information (PI) header.
//
// macOS prepends a 4-byte family identifier header (e.g., AF_INET or AF_INET6) to every read raw packet
// and expects the same 4-byte header prepended on write operations.
type tunReadCloser struct {
	f io.ReadWriteCloser

	rMu  sync.Mutex
	rBuf []byte

	wMu  sync.Mutex
	wBuf []byte
}

var _ io.ReadWriteCloser = (*tunReadCloser)(nil)

// Read strips the 4-byte macOS Packet Information header from incoming packets.
func (t *tunReadCloser) Read(to []byte) (int, error) {
	t.rMu.Lock()
	defer t.rMu.Unlock()

	neededLen := len(to) + 4
	if cap(t.rBuf) < neededLen {
		t.rBuf = make([]byte, neededLen)
	} else {
		t.rBuf = t.rBuf[:neededLen]
	}

	n, err := t.f.Read(t.rBuf)
	if n < 4 {
		if err != nil {
			return 0, err
		}
		return 0, io.ErrUnexpectedEOF
	}

	// Strip the 4-byte protocol header and copy remaining payload
	copy(to, t.rBuf[4:n])
	return n - 4, err
}

// Write prepends the required 4-byte Packet Information header (AF_INET / AF_INET6)
// before passing the raw IP packet to the kernel driver.
func (t *tunReadCloser) Write(from []byte) (int, error) {
	if len(from) == 0 {
		return 0, syscall.EIO
	}

	t.wMu.Lock()
	defer t.wMu.Unlock()

	neededLen := len(from) + 4
	if cap(t.wBuf) < neededLen {
		t.wBuf = make([]byte, neededLen)
	} else {
		t.wBuf = t.wBuf[:neededLen]
	}

	// Reset header bytes
	t.wBuf[0], t.wBuf[1], t.wBuf[2] = 0, 0, 0

	// Inspect the IP Version from the packet header (high 4 bits of the first byte)
	ipVer := from[0] >> 4
	switch ipVer {
	case 4:
		t.wBuf[3] = syscall.AF_INET
	case 6:
		t.wBuf[3] = syscall.AF_INET6
	default:
		return 0, errors.New("unable to determine IP version from packet header")
	}

	copy(t.wBuf[4:], from)

	n, err := t.f.Write(t.wBuf)
	if n < 4 {
		if err != nil {
			return 0, err
		}
		return 0, io.ErrShortWrite
	}

	return n - 4, err
}

// Close closes the underlying interface descriptor.
func (t *tunReadCloser) Close() error {
	return t.f.Close()
}
