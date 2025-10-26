PROGRAM_ARGS := --syscalls execve --filename ls,echo,iptables

all: clean compile
.PHONY: all 

run: compile
	sudo ./tracepoint_execve $(program-args)

compile: gen
	go build -o tracepoint_execve

gen:
	go generate

clean:
	- rm ebpf_bpf*.go
	- rm ebpf_bpf*.o
	- rm tracepoint_execve

