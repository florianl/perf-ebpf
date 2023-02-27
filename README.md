perf-ebpf
=========

The purpose of this repository is to showcase the use of [eBPF](https://ebpf.io/) on [perf events](https://man7.org/linux/man-pages/man2/perf_event_open.2.html) using different dependencies. By no means is the list of selected dependencies exhaustive. Contributions showcasing the use of [eBPF](https://ebpf.io/) on [perf events](https://man7.org/linux/man-pages/man2/perf_event_open.2.html) with new dependencies are welcome.

Dependencies
------------

The table below lists dependencies that provide some kind of interaction with the API of the perf subsystem of the Linux kernel. More specialized and narrow dependencies that only implement a smaller subset of the perf subsystem API are not listed.

| Dependency | Comment |
| --- | --- |
| [hodgesds/perf-utils](https://github.com/hodgesds/perf-utils#bpf-support) | [Limits the support](https://github.com/hodgesds/perf-utils#bpf-support) of eBPF to tracepoints. | 
| [golang.org/x/sys/unix/](https://pkg.go.dev/golang.org/x/sys/unix)| Provides a low level API to the perf subsystem and other Linux Kernel APIs.|
| [acln0/perf](https://github.com/acln0/perf) && [elastic/go-perf](https://github.com/elastic/go-perf) | Higher level API for the perf subsystem. [CL#168059](https://go-review.googlesource.com/c/sys/+/168059)

Use case
--------
The perf subsystem of the Linux Kernel provides a very powerful and complex API. For comparission purposes each showcase should meet the following criteria:

- Use a sampling frequency of 99 Hz
- Call eBPF program on specific PID
- Call eBPF program on every CPU
