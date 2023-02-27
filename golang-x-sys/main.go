package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	example "github.com/florianl/perf-ebpf/prog"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Expected: ./%s <PID>\n", os.Args[0])
		return
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse pid from '%s': %v", os.Args[1], err)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update rlimit: %v", err)
		return
	}

	progSpec := example.GetEbpfProg()

	// Load the ebpf program into the kernel.
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load ebpf program: %s", err)
		return
	}
	defer prog.Close()

	// Create perf event.
	ev, err := unix.PerfEventOpen(
		&unix.PerfEventAttr{
			Type:        unix.PERF_TYPE_SOFTWARE,
			Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
			Sample_type: unix.PERF_SAMPLE_RAW,
			Sample:      99, // Sampling Frequency
			Bits:        unix.PerfBitFreq,
		},
		pid,
		-1, // Sample on every CPU
		-1,
		unix.PERF_FLAG_FD_CLOEXEC,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create the perf event: %v", err)
		return
	}
	defer unix.Close(ev)

	// Attach ebpf program to perf event.
	if err := unix.IoctlSetInt(ev, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach eBPF program to perf event: %v", err)
		return
	}

	// Enable perf event.
	if err := unix.IoctlSetInt(ev, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable perf event: %v", err)
		return
	}
	defer unix.IoctlSetInt(ev, unix.PERF_EVENT_IOC_DISABLE, 0)

	// Check output via `bpftool prog tracelog`
	<-ctx.Done()
}
