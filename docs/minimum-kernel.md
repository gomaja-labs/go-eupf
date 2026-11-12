# Testing the minimum Linux kernel

The minimum is Ubuntu's Linux **5.15.0-25-generic** (5.15.0-25.25). The eBPF
load and packet tests also run on the current development kernel. A newer
host kernel alone does not validate the minimum.

`scripts/ci/test-kernel.py` builds a small initramfs around an already-built,
statically linked test binary, static BusyBox, iproute2 and the matching veth
and dummy modules. It boots KVM with no external network interface and runs the
packet and rule tests. Test processes create private network/mount namespaces.
The script requires `qemu-system-x86_64`, `ip`, `ldd`, Python 3 and access to
`/dev/kvm`; it never attaches XDP to a host interface.

Build the test executable in the privileged development image after generation:

```sh
go generate ./cmd/...
CGO_ENABLED=0 go test -c ./cmd/ebpf -o bin/ebpf-kernel.test
```

Extract a matching kernel and its modules, and a static BusyBox. These upstream
Ubuntu packages were used for the GA-kernel validation:

- [Kernel image](https://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/linux-image-5.15.0-25-generic_5.15.0-25.25_amd64.deb)
- [Kernel modules](https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-5.15.0-25-generic_5.15.0-25.25_amd64.deb)
- [Static BusyBox](https://archive.ubuntu.com/ubuntu/pool/main/b/busybox/busybox-static_1.30.1-7ubuntu3_amd64.deb)

For packages extracted below `kernel-root`, run:

```sh
sudo scripts/ci/test-kernel.py \
  --kernel kernel-root/boot/vmlinuz-5.15.0-25-generic \
  --modules-dir kernel-root/lib/modules/5.15.0-25-generic \
  --busybox kernel-root/bin/busybox \
  --test-binary bin/ebpf-kernel.test \
  --output-dir kernel-results
```

A successful run prints `qemu_exit=0 test_exit=0`. `result.json` records the
kernel, executable, modules, runtime libraries, initramfs and log hashes. Both
the QEMU exit and the guest test exit must pass. `boot.log` retains verifier
failures and the individual packet-test results. `--pattern` selects a narrower
regression; the default includes the packet paths, transaction journal, grace
ordering and old-packet/URR-reuse tests. This script is the reproducible KVM
entry point; CI runner KVM access and the complete fresh-image job duration
must be established before adding a hosted CI job.

The programs keep explicit unsigned bounds on wire lengths for the 5.15
verifier and initialize the padding passed to global BPF subprograms. Router
Solicitation processing has a separate verifier budget. Its tail-call
continuation carries IDs/flags in the packet's private headroom and restores
the original frame before parsing or forwarding; it carries no kernel pointer
or CPU-shared state. Normal data forwarding does not take that continuation.
