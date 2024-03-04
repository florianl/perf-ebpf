package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/hodgesds/perf-utils"

	example "github.com/florianl/perf-ebpf/prog"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Expected: ./%s <PID>\n", os.Args[0])
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("Failed to parse pid from '%s': %v", os.Args[1], err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to update rlimit: %v", err)
	}

	progSpec := example.GetEbpfProg()

	// Instantiate and insert the program into the kernel.
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		log.Fatalf("Creating ebpf program: %s", err)
	}
	defer prog.Close()

	sp, err := perf.NewSoftwareProfiler(pid, -1, perf.CpuClockProfiler)
	if err != nil {
		panic(err)
	}
	defer sp.Close()

	sp.Start()

	<-ctx.Done()
}
