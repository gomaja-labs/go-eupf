#!/usr/bin/env python3
"""Boot a supplied kernel and run a static eBPF test binary in an isolated VM."""

import argparse
import gzip
import hashlib
import json
import pathlib
import re
import shlex
import shutil
import stat
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=pathlib.Path, required=True)
    parser.add_argument("--test-binary", type=pathlib.Path, required=True)
    parser.add_argument("--busybox", type=pathlib.Path, required=True)
    parser.add_argument("--modules-dir", type=pathlib.Path)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--pattern", default=".")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    for path in (args.kernel, args.test_binary, args.busybox):
        if not path.is_file():
            parser.error(f"file does not exist: {path}")
    qemu = shutil.which("qemu-system-x86_64")
    ip = shutil.which("ip")
    if not qemu or not ip:
        parser.error("qemu-system-x86_64 and iproute2 ip must be installed")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive = bytearray()
    inode = 1
    directories = set()
    inputs = []

    def entry(name, mode, data=b""):
        nonlocal inode
        name = name.encode() + b"\0"
        fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0)
        inode += 1
        archive.extend(b"070701" + b"".join(f"{field:08x}".encode() for field in fields) + name)
        archive.extend(b"\0" * (-len(archive) % 4))
        archive.extend(data)
        archive.extend(b"\0" * (-len(archive) % 4))

    def directory(name):
        if name and name not in directories:
            entry(name, stat.S_IFDIR | 0o755)
            directories.add(name)

    def add_file(source, target):
        source = pathlib.Path(source)
        for parent in reversed(pathlib.PurePosixPath(target).parents):
            if str(parent) != ".":
                directory(str(parent))
        data = source.read_bytes()
        entry(target, stat.S_IFREG | 0o755, data)
        inputs.append({"path": str(source.resolve()), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    for name in ("bin", "dev", "proc", "sys", "tmp"):
        directory(name)
    add_file(args.busybox, "bin/busybox")
    add_file(args.test_binary, "test")
    add_file(ip, ip.lstrip("/"))
    dependencies = subprocess.check_output(["ldd", ip], text=True)
    for line in dependencies.splitlines():
        match = re.search(r"(/\S+)", line)
        if match:
            path = match.group(1)
            add_file(path, path.lstrip("/"))
    module_commands = []
    if args.modules_dir:
        for name in ("veth", "dummy"):
            module = args.modules_dir / "kernel/drivers/net" / f"{name}.ko"
            if module.is_file():
                add_file(module, f"{name}.ko")
                module_commands.append(f"insmod /{name}.ko")
    init = "\n".join([
        "#!/bin/busybox sh", "/bin/busybox --install -s /bin",
        "mount -t proc proc /proc", "mount -t sysfs sysfs /sys",
        "mount -t devtmpfs devtmpfs /dev", "mount -t bpf bpf /sys/fs/bpf",
        *module_commands, "ulimit -l unlimited", "uname -a",
        f"PATH={shlex.quote(str(pathlib.Path(ip).parent))}:/bin /test -test.v -test.failfast -test.run {shlex.quote(args.pattern)} -test.timeout {args.timeout}s",
        "status=$?", 'echo "KERNEL_TEST_EXIT=$status"', "poweroff -f", "",
    ])
    entry("init", stat.S_IFREG | 0o755, init.encode())
    entry("TRAILER!!!", 0)
    initramfs = args.output_dir / "initramfs.gz"
    initramfs.write_bytes(gzip.compress(bytes(archive), mtime=0))
    command = [qemu, "-enable-kvm", "-cpu", "host", "-m", "2048", "-smp", "2", "-no-reboot", "-nographic", "-nic", "none", "-kernel", str(args.kernel.resolve()), "-initrd", str(initramfs.resolve()), "-append", "console=ttyS0 rdinit=/init panic=-1"]
    log = args.output_dir / "boot.log"
    with log.open("wb") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=args.timeout + 60, check=False)
    text = log.read_text(errors="replace")
    matches = re.findall(r"KERNEL_TEST_EXIT=(\d+)", text)
    status = int(matches[-1]) if matches else None
    kernel = args.kernel.read_bytes()
    metadata = {"command": command, "qemu_exit": result.returncode, "test_exit": status, "pattern": args.pattern,
                "kernel_sha256": hashlib.sha256(kernel).hexdigest(), "inputs": inputs,
                "initramfs_sha256": hashlib.sha256(initramfs.read_bytes()).hexdigest(),
                "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                "passed_test_rows": len(re.findall(r"^\s*--- PASS:", text, re.MULTILINE))}
    (args.output_dir / "result.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"qemu_exit={result.returncode} test_exit={status} log={log}")
    return 0 if result.returncode == 0 and status == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
