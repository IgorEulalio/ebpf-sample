all: gen compile
.PHONY: all 

gen: sync
	go generate

compile: sync
	go build -o kprobe_reader

clean: sync
	- rm ebpf_bpf*.go
	- rm ebpf_bpf*.o
	- rm kprobe_reader

sync:
	cp -r /Users/igorlopes/Documents/personal/ebpf-sample ~/projects/
