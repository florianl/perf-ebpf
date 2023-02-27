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

	"github.com/elastic/go-perf"

	example "github.com/florianl/perf-ebpf/prog"
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

	// Prepare perf event.
	pfa := new(perf.Attr)
	pfa.SetSampleFreq(99)
	perf.CPUClock.Configure(pfa)

	// Create perf event.
	ev, err := perf.Open(pfa, pid, perf.AnyCPU, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create perf event: %v", err)
		return
	}
	defer ev.Close()

	// Attach ebpf program to perf event.
	if err := ev.SetBPF(uint32(prog.FD())); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach eBPF program to event: %v", err)
		return
	}

	// Enable perf event.
	if err := ev.Enable(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable event: %v", err)
	}
	defer ev.Disable()

	// Check output via `bpftool prog tracelog`
	<-ctx.Done()
}
