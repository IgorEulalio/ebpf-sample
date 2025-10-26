# eBPF Execution Tracer

Monitor program executions system-wide using eBPF.

It currently only supports tracking execve syscall.

## Prerequisites

```bash
# Install eBPF toolchain
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    golang-go \
    make
```

## Build

```bash
make
```

## Run

```bash
# Monitor all executions of execve
sudo ./tracepoint_execve

# Filter by specific programs
sudo ./tracepoint_execve --filename ls,cat,grep
```

## Example Output

```
tracepoint_execve: 19:45:00 pid: 1234    comm: ls     path: /usr/bin/ls      comm_with_args: [ls -lha /tmp]
tracepoint_execve: 19:45:01 pid: 1235    comm: cat    path: /usr/bin/cat     comm_with_args: [cat /etc/hostname]
tracepoint_execve: 19:45:02 pid: 1236    comm: grep   path: /usr/bin/grep    comm_with_args: [grep -i test file.txt]
```

## Clean

```bash
make clean
```
