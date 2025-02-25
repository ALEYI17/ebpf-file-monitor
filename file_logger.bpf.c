//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_SIZE 150
#define PATH_MAX 256

char __license[] SEC("license") = "Dual MIT/GPL";


struct file_event{
  u32 pid;
  u32 uid;
  u8 comm[TASK_COMM_SIZE];
  u8 filename[PATH_MAX];
  int flags;
  u64 timestamp_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

const struct file_event *unused __attribute__((unused));

SEC("ksyscall/open")
int BPF_KPROBE_SYSCALL(handle_open,const char *pathname, int flags, mode_t mode) {

  struct file_event *event;

  event = bpf_ringbuf_reserve(&events,sizeof(struct file_event),0);
  if(!event) return 0;

  event->pid = bpf_get_current_pid_tgid() >> 32;

  event->uid = bpf_get_current_uid_gid() >>32;

  bpf_get_current_comm(&event->comm,TASK_COMM_SIZE);

  bpf_probe_read_str(event->filename,sizeof(event->filename),pathname);

  event->flags = flags;

  event->timestamp_ns = bpf_ktime_get_ns();
  
  bpf_ringbuf_submit(event,0);

  return 0;
} 
