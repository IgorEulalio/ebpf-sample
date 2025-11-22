#!/bin/sh
# curl trough syscall lens
strace -e trace=connect,sendto,recvfrom curl google.com

# run demo
gcc -o demo syscalls.c
strace -e trace=openat,close,read,write ./demo