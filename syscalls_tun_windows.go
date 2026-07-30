package water

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// Wintun High-Throughput Adaptive Spin-Loop Constants
const (
	// rateMeasurementGranularity defines the measurement window (500ms) for rate estimation.
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)

	// spinloopRateThreshold represents the throughput threshold (100 MB/s = 800 Mbps)
	// above which Read() enters a low-latency spin-loop instead of immediately sleeping on a Win32 event handle.
	spinloopRateThreshold = 800000000 / 8

	// spinloopDuration (~12.5 microseconds) limits CPU spinning duration before falling back to WaitForSingleObject.
	spinloopDuration = uint64(time.Millisecond / 80 / time.Nanosecond)
)

// Event bitmask representing interface status changes.
type Event int

const (
	EventUp Event = 1 << iota
	EventDown
	EventMTUUpdate
)

// rateJuggler provides a lock-free, atomic throughput tracker used to dynamically trigger
// low-latency CPU spin-loops during high-bandwidth packet transfers.
type rateJuggler struct {
	current       uint64 // Estimated current transfer rate (bytes per second)
	nextByteCount uint64 // Accumulated byte count in the current window
	nextStartTime int64  // Start timestamp (nanoseconds) of the active window
	changing      int32  // Atomic CAS flag (0: idle, 1: updating state)
}

// NativeTun implements the low-level native Wintun driver interface.
// Wintun utilizes a shared-memory ring buffer between kernel and user space for zero-copy I/O.
type NativeTun struct {
	wt        *wintun.Adapter
	name      string
	handle    windows.Handle
	rate      rateJuggler
	session   wintun.Session
	readWait  windows.Handle
	events    chan Event
	running   sync.WaitGroup
	closeOnce sync.Once
	close     int32 // Atomic boolean flag (1 if interface is closing/closed)
	forcedMTU int
}

// WTun wraps NativeTun to implement the standard Go io.ReadWriteCloser interface.
type WTun struct {
	dev *NativeTun
}

func (w *WTun) Close() error {
	return w.dev.Close()
}

func (w *WTun) Write(b []byte) (int, error) {
	return w.dev.Write(b, 0)
}

func (w *WTun) Read(b []byte) (int, error) {
	return w.dev.Read(b, 0)
}

var (
	// WintunTunnelType identifies the tunnel adapter description shown in Windows Network Connections.
	WintunTunnelType = "Wintun"

	// WintunStaticRequestedGUID holds optional static GUID for adapter creation.
	WintunStaticRequestedGUID *windows.GUID
)

// Linkname internal Go runtime routines for high-precision time and processor yielding.
//
//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

// openTunDev initializes and instantiates a native Wintun adapter using a pre-defined static GUID.
func openTunDev(config Config) (ifce *Interface, err error) {
	// Standard static GUID for Water Wintun interface instance
	gUID := &windows.GUID{
		Data1: 0x00000000,
		Data2: 0xFFFF,
		Data3: 0xFFFF,
		Data4: [8]byte{0xFF, 0xE9, 0x76, 0xE5, 0x8C, 0x74, 0x06, 0x3E},
	}

	ifName := config.PlatformSpecificParams.Name
	if ifName == "" {
		ifName = "WaterIface"
	}

	nativeTunDevice, err := CreateTUNWithRequestedGUID(ifName, gUID, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create Wintun native device: %w", err)
	}

	ifce = &Interface{
		isTAP:           config.DeviceType == TAP,
		ReadWriteCloser: &WTun{dev: nativeTunDevice},
		name:            ifName,
	}
	return ifce, nil
}

// CreateTUN creates or reuses a Wintun adapter interface with the given name and default GUID.
func CreateTUN(ifname string, mtu int) (*NativeTun, error) {
	return CreateTUNWithRequestedGUID(ifname, WintunStaticRequestedGUID, mtu)
}

// CreateTUNWithRequestedGUID creates or reuses a Wintun adapter interface with a specific GUID.
// Allocates an 8 MiB shared kernel ring buffer session for high performance.
func CreateTUNWithRequestedGUID(ifname string, requestedGUID *windows.GUID, mtu int) (*NativeTun, error) {
	wt, err := wintun.CreateAdapter(ifname, WintunTunnelType, requestedGUID)
	if err != nil {
		return nil, fmt.Errorf("error creating Wintun adapter: %w", err)
	}

	forcedMTU := 1420
	if mtu > 0 {
		forcedMTU = mtu
	}

	tun := &NativeTun{
		wt:        wt,
		name:      ifname,
		handle:    windows.InvalidHandle,
		events:    make(chan Event, 10),
		forcedMTU: forcedMTU,
	}

	// Initialize 8 MiB (0x800000 bytes) shared-memory ring buffer session
	tun.session, err = wt.StartSession(0x800000)
	if err != nil {
		_ = tun.wt.Close()
		close(tun.events)
		return nil, fmt.Errorf("error starting Wintun session: %w", err)
	}

	tun.readWait = tun.session.ReadWaitEvent()
	return tun, nil
}

// Name returns the device adapter interface name.
func (tun *NativeTun) Name() (string, error) {
	return tun.name, nil
}

// File returns nil as Wintun relies on shared memory ring buffers rather than OS file handles.
func (tun *NativeTun) File() *os.File {
	return nil
}

// Events returns the channel broadcasting interface lifecycle and MTU updates.
func (tun *NativeTun) Events() chan Event {
	return tun.events
}

// Close gracefully terminates the Wintun ring buffer session and closes the interface handle.
func (tun *NativeTun) Close() error {
	var err error
	tun.closeOnce.Do(func() {
		atomic.StoreInt32(&tun.close, 1)

		// Signal readWait handle to unblock any pending Read calls
		_ = windows.SetEvent(tun.readWait)

		// Wait for active Read/Write operations to finish
		tun.running.Wait()

		tun.session.End()
		if tun.wt != nil {
			err = tun.wt.Close()
		}
		close(tun.events)
	})
	return err
}

// MTU returns the currently configured MTU.
func (tun *NativeTun) MTU() (int, error) {
	return tun.forcedMTU, nil
}

// ForceMTU overrides the interface MTU and notifies channel listeners if updated.
func (tun *NativeTun) ForceMTU(mtu int) {
	if tun.forcedMTU != mtu {
		tun.forcedMTU = mtu
		select {
		case tun.events <- EventMTUUpdate:
		default:
		}
	}
}

// Read copies an incoming packet from the Wintun ring buffer into `buff[offset:]`.
//
// Performance Optimization:
// When network traffic exceeds `spinloopRateThreshold` (800 Mbps), Read enters a brief CPU spin loop
// calling `procyield(1)` before blocking on `WaitForSingleObject`. This avoids Win32 event context-switches,
// achieving line-rate throughput on 1Gbps+ interfaces.
func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	if offset < 0 || offset > len(buff) {
		return 0, fmt.Errorf("invalid read buffer offset: %d", offset)
	}

	tun.running.Add(1)
	defer tun.running.Done()

retry:
	if atomic.LoadInt32(&tun.close) == 1 {
		return 0, os.ErrClosed
	}

	start := nanotime()
	shouldSpin := atomic.LoadUint64(&tun.rate.current) >= spinloopRateThreshold &&
		uint64(start-atomic.LoadInt64(&tun.rate.nextStartTime)) <= rateMeasurementGranularity*2

	for {
		if atomic.LoadInt32(&tun.close) == 1 {
			return 0, os.ErrClosed
		}

		packet, err := tun.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			if len(buff)-offset < packetSize {
				tun.session.ReleaseReceivePacket(packet)
				return 0, fmt.Errorf("buffer space (%d bytes) too small for packet (%d bytes)", len(buff)-offset, packetSize)
			}

			copy(buff[offset:], packet)
			tun.session.ReleaseReceivePacket(packet)

			tun.rate.update(uint64(packetSize))
			return packetSize, nil

		case windows.ERROR_NO_MORE_ITEMS:
			// Ring buffer empty: check if we should spin or block
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				_, _ = windows.WaitForSingleObject(tun.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1) // Yield execution to sibling hyperthreads
			continue

		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed

		case windows.ERROR_INVALID_DATA:
			return 0, errors.New("Wintun receive ring buffer corrupt")
		}

		return 0, fmt.Errorf("Wintun Read failed: %w", err)
	}
}

// Flush is a no-op required for stream interface compatibility.
func (tun *NativeTun) Flush() error {
	return nil
}

// Write allocates a packet slice in the Wintun transmit ring buffer and copies `buff[offset:]`.
func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {
	if offset < 0 || offset > len(buff) {
		return 0, fmt.Errorf("invalid write buffer offset: %d", offset)
	}

	tun.running.Add(1)
	defer tun.running.Done()

	if atomic.LoadInt32(&tun.close) == 1 {
		return 0, os.ErrClosed
	}

	packetSize := len(buff) - offset
	if packetSize == 0 {
		return 0, nil
	}

	tun.rate.update(uint64(packetSize))

	packet, err := tun.session.AllocateSendPacket(packetSize)
	if err == nil {
		copy(packet, buff[offset:])
		tun.session.SendPacket(packet)
		return packetSize, nil
	}

	switch err {
	case windows.ERROR_HANDLE_EOF:
		return 0, os.ErrClosed
	case windows.ERROR_BUFFER_OVERFLOW:
		// Ring buffer full: drop packet gracefully according to TUN/TAP network interface semantics
		return 0, nil
	}

	return 0, fmt.Errorf("Wintun Write failed: %w", err)
}

// LUID returns the Windows Network Interface Locally Unique Identifier (LUID).
func (tun *NativeTun) LUID() uint64 {
	tun.running.Add(1)
	defer tun.running.Done()

	if atomic.LoadInt32(&tun.close) == 1 {
		return 0
	}
	return tun.wt.LUID()
}

// RunningVersion returns the active driver version of the loaded Wintun DLL/sys driver.
func (tun *NativeTun) RunningVersion() (version uint32, err error) {
	return wintun.RunningVersion()
}

// update calculates sliding-window throughput rate using non-blocking atomic operations.
func (rate *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := atomic.AddUint64(&rate.nextByteCount, packetLen)
	period := uint64(now - atomic.LoadInt64(&rate.nextStartTime))

	if period >= rateMeasurementGranularity {
		// Attempt lock-free state transition (0 -> 1)
		if !atomic.CompareAndSwapInt32(&rate.changing, 0, 1) {
			return
		}

		atomic.StoreInt64(&rate.nextStartTime, now)
		// Calculate bytes per second: (bytes * 1e9 ns) / period_ns
		if period > 0 {
			atomic.StoreUint64(&rate.current, total*uint64(time.Second/time.Nanosecond)/period)
		}
		atomic.StoreUint64(&rate.nextByteCount, 0)

		// Release lock-free state (1 -> 0)
		atomic.StoreInt32(&rate.changing, 0)
	}
}
