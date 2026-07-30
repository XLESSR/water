package water

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// Windows TAP Adapter Drivers:
// Requirements: OpenVPN TAP-Windows6 driver installed on Windows.
// Reference: https://github.com/OpenVPN/tap-windows6 or OpenVPN installer.

const (
	// tapDriverKey locates network adapter class devices in Windows Registry ({4D36E972-E325-11CE-BFC1-08002BE10318}).
	tapDriverKey = `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`

	// netConfigKey locates network connection settings in Windows Registry.
	netConfigKey = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`
)

var (
	errIfceNameNotFound = errors.New("Failed to find the name of interface")

	// TAP-Windows IOCTL Device Control Codes derived via tap_control_code()
	tap_win_ioctl_get_mac             = tap_control_code(1, 0)
	tap_win_ioctl_get_version         = tap_control_code(2, 0)
	tap_win_ioctl_get_mtu             = tap_control_code(3, 0)
	tap_win_ioctl_get_info            = tap_control_code(4, 0)
	tap_ioctl_config_point_to_point   = tap_control_code(5, 0)
	tap_ioctl_set_media_status        = tap_control_code(6, 0)
	tap_win_ioctl_config_dhcp_masq    = tap_control_code(7, 0)
	tap_win_ioctl_get_log_line        = tap_control_code(8, 0)
	tap_win_ioctl_config_dhcp_set_opt = tap_control_code(9, 0)
	tap_ioctl_config_tun              = tap_control_code(10, 0)

	// Windows API Constants
	file_device_unknown = uint32(0x00000022) // FILE_DEVICE_UNKNOWN

	// kernel32.dll Function Procedure Pointers
	nCreateEvent,
	nResetEvent,
	nGetOverlappedResult uintptr
)

func init() {
	k32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		panic("failed to load kernel32.dll: " + err.Error())
	}
	defer syscall.FreeLibrary(k32)

	nCreateEvent = getProcAddr(k32, "CreateEventW")
	nResetEvent = getProcAddr(k32, "ResetEvent")
	nGetOverlappedResult = getProcAddr(k32, "GetOverlappedResult")
}

// getProcAddr resolves exported procedure address from a loaded Windows DLL.
func getProcAddr(lib syscall.Handle, name string) uintptr {
	addr, err := syscall.GetProcAddress(lib, name)
	if err != nil {
		panic("failed to locate procedure " + name + ": " + err.Error())
	}
	return addr
}

// resetEvent resets the state of an event object to non-signaled (Win32 ResetEvent).
func resetEvent(h syscall.Handle) error {
	r, _, err := syscall.Syscall(nResetEvent, 1, uintptr(h), 0, 0)
	if r == 0 {
		return err
	}
	return nil
}

// getOverlappedResult retrieves the status/transferred bytes of an asynchronous I/O operation.
func getOverlappedResult(h syscall.Handle, overlapped *syscall.Overlapped) (int, error) {
	var bytesTransferred int
	r, _, err := syscall.Syscall6(
		nGetOverlappedResult,
		4,
		uintptr(h),
		uintptr(unsafe.Pointer(overlapped)),
		uintptr(unsafe.Pointer(&bytesTransferred)),
		1, // bWait = TRUE (block until completed)
		0,
		0,
	)
	if r == 0 {
		return bytesTransferred, err
	}
	return bytesTransferred, nil
}

// newOverlapped creates a manual-reset event object wrapped in a syscall.Overlapped structure.
func newOverlapped() (*syscall.Overlapped, error) {
	// CreateEventW(lpEventAttributes, bManualReset=TRUE, bInitialState=FALSE, lpName=NULL)
	r, _, err := syscall.Syscall6(nCreateEvent, 4, 0, 1, 0, 0, 0, 0)
	if r == 0 {
		return nil, err
	}
	return &syscall.Overlapped{HEvent: syscall.Handle(r)}, nil
}

// wfile wraps a Windows file handle using Win32 Overlapped (Asynchronous) I/O.
type wfile struct {
	fd syscall.Handle
	rl sync.Mutex
	wl sync.Mutex
	ro *syscall.Overlapped
	wo *syscall.Overlapped
}

func (f *wfile) Close() error {
	return syscall.Close(f.fd)
}

func (f *wfile) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	f.wl.Lock()
	defer f.wl.Unlock()

	if err := resetEvent(f.wo.HEvent); err != nil {
		return 0, err
	}

	var bytesWritten uint32
	err := syscall.WriteFile(f.fd, b, &bytesWritten, f.wo)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return int(bytesWritten), err
	}

	// Block until asynchronous write completes
	return getOverlappedResult(f.fd, f.wo)
}

func (f *wfile) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	f.rl.Lock()
	defer f.rl.Unlock()

	if err := resetEvent(f.ro.HEvent); err != nil {
		return 0, err
	}

	var bytesRead uint32
	err := syscall.ReadFile(f.fd, b, &bytesRead, f.ro)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return int(bytesRead), err
	}

	// Block until asynchronous read completes
	return getOverlappedResult(f.fd, f.ro)
}

// ctl_code calculates Win32 Control Codes:
// CTL_CODE(DeviceType, Function, Method, Access) = ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)
func ctl_code(device_type, function, method, access uint32) uint32 {
	return (device_type << 16) | (access << 14) | (function << 2) | method
}

// tap_control_code creates device control codes for the TAP-Windows driver.
func tap_control_code(request, method uint32) uint32 {
	return ctl_code(file_device_unknown, request, method, 0)
}

// getdeviceid queries Windows Registry to locate the NetCfgInstanceId GUID of a TAP device
// matching the provided ComponentID (e.g., "tap0901") and optionally InterfaceName.
func getdeviceid(componentID string, interfaceName string) (deviceid string, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tapDriverKey, registry.READ)
	if err != nil {
		return "", fmt.Errorf("failed to open network adapter registry key, TAP driver may not be installed: %w", err)
	}
	defer k.Close()

	keys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}

	for _, v := range keys {
		foundID, matched := func(subKeyName string) (string, bool) {
			subKeyPath := tapDriverKey + `\` + subKeyName
			key, err := registry.OpenKey(registry.LOCAL_MACHINE, subKeyPath, registry.READ)
			if err != nil {
				return "", false
			}
			defer key.Close()

			val, _, err := key.GetStringValue("ComponentId")
			if err != nil || val != componentID {
				return "", false
			}

			netInstanceID, _, err := key.GetStringValue("NetCfgInstanceId")
			if err != nil {
				return "", false
			}

			// Validate interface name if specified
			if len(interfaceName) > 0 {
				connKeyPath := fmt.Sprintf(`%s\%s\Connection`, netConfigKey, netInstanceID)
				connKey, err := registry.OpenKey(registry.LOCAL_MACHINE, connKeyPath, registry.READ)
				if err != nil {
					return "", false
				}
				defer connKey.Close()

				nameVal, _, err := connKey.GetStringValue("Name")
				if err != nil || nameVal != interfaceName {
					return "", false
				}
			}

			return netInstanceID, true
		}(v)

		if matched {
			return foundID, nil
		}
	}

	if len(interfaceName) > 0 {
		return "", fmt.Errorf("failed to find tap device in registry with ComponentId '%s' and InterfaceName '%s'", componentID, interfaceName)
	}
	return "", fmt.Errorf("failed to find tap device in registry with ComponentId '%s'", componentID)
}

// setStatus toggles interface link state (Media Status UP = true / DOWN = false).
func setStatus(fd syscall.Handle, status bool) error {
	var bytesReturned uint32
	rdbbuf := make([]byte, syscall.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	code := [4]byte{0x00, 0x00, 0x00, 0x00}
	if status {
		code[0] = 0x01
	}

	return syscall.DeviceIoControl(
		fd,
		tap_ioctl_set_media_status,
		&code[0],
		uint32(len(code)),
		&rdbbuf[0],
		uint32(len(rdbbuf)),
		&bytesReturned,
		nil,
	)
}

// setTUN sends IP configuration (local IP, network/remote IP, netmask) to TAP driver in TUN mode.
func setTUN(fd syscall.Handle, network string) error {
	var bytesReturned uint32
	rdbbuf := make([]byte, syscall.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)

	localIP, remoteNet, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("failed to parse network CIDR (%s): %w", network, err)
	}

	localIPv4 := localIP.To4()
	if localIPv4 == nil {
		return fmt.Errorf("provided network (%s) is not a valid IPv4 address", network)
	}

	remoteIPv4 := remoteNet.IP.To4()
	if remoteIPv4 == nil {
		return fmt.Errorf("provided remote network (%s) is not a valid IPv4 address", network)
	}

	// Payload layout (12 bytes): [4-byte local IP][4-byte remote IP/network][4-byte netmask]
	code2 := make([]byte, 12)
	copy(code2[0:4], localIPv4)
	copy(code2[4:8], remoteIPv4)
	copy(code2[8:12], remoteNet.Mask)

	return syscall.DeviceIoControl(
		fd,
		tap_ioctl_config_tun,
		&code2[0],
		uint32(len(code2)),
		&rdbbuf[0],
		uint32(len(rdbbuf)),
		&bytesReturned,
		nil,
	)
}

// openDev discovers, creates, and initializes a TAP/TUN device interface on Windows.
func openDev(config Config) (ifce *Interface, err error) {
	if config.DeviceType == TUN {
		return openTunDev(config)
	}

	// Locate TAP device GUID in Windows Registry
	deviceid, err := getdeviceid(config.PlatformSpecificParams.ComponentID, config.PlatformSpecificParams.Name)
	if err != nil {
		return nil, err
	}

	path := `\\.\Global\` + deviceid + `.tap`
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	// Open handle to TAP virtual file descriptor with FILE_FLAG_OVERLAPPED enabled
	file, err := syscall.CreateFile(
		pathp,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		uint32(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE),
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_SYSTEM|syscall.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			_ = syscall.Close(file)
		}
		if r := recover(); r != nil {
			_ = syscall.Close(file)
			panic(r) // Preserve panic behavior after resource cleanup
		}
	}()

	var bytesReturned uint32

	// Query MAC address of TAP adapter
	mac := make([]byte, 6)
	err = syscall.DeviceIoControl(
		file,
		tap_win_ioctl_get_mac,
		&mac[0],
		uint32(len(mac)),
		&mac[0],
		uint32(len(mac)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TAP MAC address via ioctl: %w", err)
	}

	ro, err := newOverlapped()
	if err != nil {
		return nil, err
	}
	wo, err := newOverlapped()
	if err != nil {
		return nil, err
	}

	fdWrapper := &wfile{fd: file, ro: ro, wo: wo}
	ifce = &Interface{isTAP: (config.DeviceType == TAP), ReadWriteCloser: fdWrapper}

	// Bring interface status UP
	if err := setStatus(file, true); err != nil {
		return nil, err
	}

	if config.DeviceType == TUN {
		if err := setTUN(file, config.PlatformSpecificParams.Network); err != nil {
			return nil, err
		}
	}

	// Match hardware MAC address against network interfaces to resolve interface name
	ifces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, v := range ifces {
		if len(v.HardwareAddr) >= 6 && bytes.Equal(v.HardwareAddr[:6], mac[:6]) {
			ifce.name = v.Name
			return ifce, nil
		}
	}

	return nil, errIfceNameNotFound
}
