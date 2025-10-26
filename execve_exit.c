// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_SIZE 100
#define ARGSIZE 128
#define MAX_ARGS 5

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    u8  comm[TASK_COMM_SIZE];
    u8  filename[ARGSIZE];
    u8  args[MAX_ARGS][ARGSIZE];  // Store up to 5 arguments
    u32 argc;                      // Number of arguments captured
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

// Map to store filename from entry to exit
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct event);
	__uint(max_entries, 10240);
} exec_info SEC(".maps");

// Per-CPU array for temporary storage (to avoid stack overflow)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct event);
	__uint(max_entries, 1);
} temp_event SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;

    if (pid != tid)
        return 0;

    // Use per-CPU array to avoid stack overflow
    u32 key = 0;
    struct event *info = bpf_map_lookup_elem(&temp_event, &key);
    if (!info)
        return 0;

    __builtin_memset(info, 0, sizeof(*info));
    info->pid = pid;
    info->argc = 0;

    // Try to read filename from user space at entry
    unsigned long filename_ptr = ctx->args[0];
    if (filename_ptr) {
        bpf_probe_read_user_str(&info->filename, sizeof(info->filename), (void *)filename_ptr);
    }

    // Try to read argv array (ctx->args[1] points to argv)
    unsigned long argv_ptr = ctx->args[1];
    if (argv_ptr) {
        // Read up to MAX_ARGS arguments
        #pragma unroll
        for (int i = 0; i < MAX_ARGS; i++) {
            unsigned long arg_ptr = 0;
            // Read the pointer to argv[i]
            long ret = bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), (void *)(argv_ptr + i * sizeof(unsigned long)));

            if (ret != 0 || arg_ptr == 0) {
                break;  // NULL pointer or read failed, end of args
            }

            // Read the string at argv[i]
            ret = bpf_probe_read_user_str(&info->args[i], ARGSIZE, (void *)arg_ptr);
            if (ret > 0) {
                info->argc++;
            } else {
                break;  // Failed to read string
            }
        }
    }

    // Store in map for retrieval at exit
    bpf_map_update_elem(&exec_info, &pid, info, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint_execve_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;

    if (pid != tid)
        return 0;

    // Only process successful execve calls (ret == 0 for execve)
    if (ctx->ret != 0) {
        bpf_map_delete_elem(&exec_info, &pid);
        return 0;
    }

    // Try to retrieve the filename we stored at entry
    struct event *stored_info = bpf_map_lookup_elem(&exec_info, &pid);

    struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		bpf_map_delete_elem(&exec_info, &pid);
		return 0;
	}

	__builtin_memset(e->filename, 0, sizeof(e->filename));
	__builtin_memset(e->comm, 0, sizeof(e->comm));

	e->pid = pid;

	// After successful execve, the task's comm has been updated to the new program name
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// If we have stored filename from entry, use it
	if (stored_info && stored_info->filename[0] != 0) {
		__builtin_memcpy(e->filename, stored_info->filename, sizeof(e->filename));
	} else {
		// Fall back to comm
		__builtin_memcpy(e->filename, e->comm, sizeof(e->comm));
	}

	// Clean up the map entry
	bpf_map_delete_elem(&exec_info, &pid);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
