//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_SIZE 150
#define PATH_MAX 256

char __license[] SEC("license") = "Dual MIT/GPL";


struct file_event{
  // host level info
  u32 pid;
  u32 uid;
  u32 gid;
  u64 cgroup_id;
  u32 ppid;
  u8 cgroup_name[TASK_COMM_SIZE];
  // userspace level info
  u32 user_pid;
  u32 user_ppid;
  // syscall info
  u8 comm[TASK_COMM_SIZE];
  u8 filename[PATH_MAX];
  int flags;
  u64 timestamp_ns;
  long ret;
  u64 latency;
  u64 timestamp_ns_exit;
};

struct rw_event{
  u32 syscall_type; // 0 :read , 1: write
  u32 pid;
  u32 uid;
  u8 comm[TASK_COMM_SIZE];
  u64 timestamp_ns;
  long ret;
  u64 latency;
  u64 timestamp_ns_exit;
  u32 fd;
  size_t count;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct file_event);
} tmp_event_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct file_event);
  __uint(max_entries, 1024);
} start_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} rb_rw SEC(".maps");

struct{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct rw_event);
  __uint(max_entries, 1024);
} start_events_rw SEC(".maps");

const struct file_event *unused __attribute__((unused));
const struct rw_event *unused2 __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_tcbtf (struct trace_event_raw_sys_enter *ctx) {
  
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 key = 0;

  struct file_event *event = bpf_map_lookup_elem(&tmp_event_map, &key);
  if (!event)
      return 0;

  // zero out memory (since it's reused)
  __builtin_memset(event, 0, sizeof(*event));

  // now fill the event as usual
  event->pid = pid_tgid >> 32;
  u64 uid_gid = bpf_get_current_uid_gid();
  event->uid = uid_gid >> 32;
  event->gid = uid_gid & 0xFFFFFFFF;
  event->cgroup_id = bpf_get_current_cgroup_id();

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  event->ppid = BPF_CORE_READ(task, real_parent, tgid);

  const char *cname = BPF_CORE_READ(task, cgroups, subsys[ memory_cgrp_id], cgroup, kn, name);
  bpf_core_read_str(event->cgroup_name, sizeof(event->cgroup_name), cname);

  struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);
  struct nsproxy *namespaceproxy = BPF_CORE_READ(task, nsproxy);
  struct pid_namespace *pid_ns_children = BPF_CORE_READ(namespaceproxy, pid_ns_for_children);
  unsigned int level = BPF_CORE_READ(pid_ns_children, level);
  event->user_pid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

  struct nsproxy *parent_namespaceproxy = BPF_CORE_READ(parent_task, nsproxy);
  struct pid_namespace *parent_pid_ns_children = BPF_CORE_READ(parent_namespaceproxy, pid_ns_for_children);
  unsigned int parent_level = BPF_CORE_READ(parent_pid_ns_children, level);
  event->user_ppid = BPF_CORE_READ(parent_task, group_leader, thread_pid, numbers[parent_level].nr);

  bpf_get_current_comm(&event->comm, TASK_COMM_SIZE);
  const char *filename = (const char *) ctx->args[1];
  bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
  event->flags = (int) ctx->args[2];
  event->timestamp_ns = bpf_ktime_get_ns();

  // finally, persist it to start_events
  bpf_map_update_elem(&start_events, &pid_tgid, event, BPF_ANY);
  return 0;  
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat_tpbtf(struct trace_event_raw_sys_exit *ctx){
  
  struct file_event *event;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  event = bpf_map_lookup_elem(&start_events,&pid_tgid);
  if (!event)
    return 0;

  struct file_event *final_event;

  final_event = bpf_ringbuf_reserve(&events,sizeof(struct file_event),0);

  if(!final_event) return 0;

  long ret = ctx->ret;

  __builtin_memcpy(final_event, event, sizeof(struct file_event));

  final_event->ret = ret;
  u64 now = bpf_ktime_get_ns();
  final_event->timestamp_ns_exit = now;
  final_event->latency = now - event->timestamp_ns;

  bpf_printk("openat returned: %ld\n", ret);

  bpf_ringbuf_submit(final_event,0);

  bpf_map_delete_elem(&start_events,&pid_tgid);
  return 0;
}


SEC("tracepoint/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter *ctx){
  struct rw_event event = {}; 
  
  u64 pid_tgid = bpf_get_current_pid_tgid();

  event.pid = pid_tgid >> 32;

  event.uid = bpf_get_current_uid_gid() >>32;

  bpf_get_current_comm(&event.comm,TASK_COMM_SIZE);

  event.fd = (u32)ctx->args[0];

  event.count = (size_t) ctx->args[2];

  event.timestamp_ns = bpf_ktime_get_ns();
  
  event.syscall_type = 0;

  bpf_map_update_elem(&start_events_rw,&pid_tgid,&event,BPF_ANY);

  return 0;
} 

SEC("tracepoint/syscalls/sys_exit_read")
int handle_exit_read(struct trace_event_raw_sys_exit *ctx){
  struct rw_event *event;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  event = bpf_map_lookup_elem(&start_events_rw,&pid_tgid);
  if (!event)
    return 0;

  struct rw_event *final_event;

  final_event = bpf_ringbuf_reserve(&rb_rw,sizeof(struct rw_event),0);

  if(!final_event) return 0;

  long ret = ctx->ret;

  final_event->pid = event->pid;

  final_event->uid = event->uid;

  bpf_probe_read_kernel_str(final_event->comm,sizeof(final_event->comm),event->comm);

  final_event->timestamp_ns = event->timestamp_ns;

  final_event->ret = ret;

  u64 now = bpf_ktime_get_ns();

  final_event->timestamp_ns_exit = now;

  final_event->latency = now - event->timestamp_ns;

  final_event->syscall_type = event->syscall_type;

  final_event->fd = event->fd;

  final_event->count = event->count;

  bpf_ringbuf_submit(final_event,0);

  bpf_map_delete_elem(&start_events_rw,&pid_tgid);

  return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter *ctx){
  struct rw_event event = {}; 
  
  u64 pid_tgid = bpf_get_current_pid_tgid();

  event.pid = pid_tgid >> 32;

  event.uid = bpf_get_current_uid_gid() >>32;

  bpf_get_current_comm(&event.comm,TASK_COMM_SIZE);

  event.fd = (u32)ctx->args[0];

  event.count = (size_t) ctx->args[2];

  event.timestamp_ns = bpf_ktime_get_ns();
  
  event.syscall_type = 1;

  bpf_map_update_elem(&start_events_rw,&pid_tgid,&event,BPF_ANY);

  return 0;
} 

SEC("tracepoint/syscalls/sys_exit_write")
int handle_exit_write(struct trace_event_raw_sys_exit *ctx){
  struct rw_event *event;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  event = bpf_map_lookup_elem(&start_events_rw,&pid_tgid);
  if (!event)
    return 0;

  struct rw_event *final_event;

  final_event = bpf_ringbuf_reserve(&rb_rw,sizeof(struct rw_event),0);

  if(!final_event) return 0;

  long ret = ctx->ret;

  final_event->pid = event->pid;

  final_event->uid = event->uid;

  bpf_probe_read_kernel_str(final_event->comm,sizeof(final_event->comm),event->comm);

  final_event->timestamp_ns = event->timestamp_ns;

  final_event->ret = ret;

  u64 now = bpf_ktime_get_ns();

  final_event->timestamp_ns_exit = now;

  final_event->latency = now - event->timestamp_ns;

  final_event->syscall_type = event->syscall_type;

  final_event->fd = event->fd;

  final_event->count = event->count;

  bpf_ringbuf_submit(final_event,0);

  bpf_map_delete_elem(&start_events_rw,&pid_tgid);

  return 0;
}






