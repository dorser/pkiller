// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 pkiller-Authors */

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#ifndef SIGKILL
#define SIGKILL 9
#endif

struct event {
  bool complete;
};

const volatile __u32 pid_to_kill = 0;
const volatile __u64 min_start_time_ns = 0;

GADGET_PARAM(pid_to_kill);
GADGET_PARAM(min_start_time_ns);
GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(pkiller, events, event);

/*
 * We use a global variable to track if we have already killed the process.
 * This is effectively a single-entry map handled by libbpf/gadget.
 */
bool killed = false;

static __always_inline int kill_process(void *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  if (killed || pid == 0 || pid != pid_to_kill) {
    return 0;
  }

  /*
   * Verify start time to prevent killing a recycled PID.
   * If min_start_time_ns is set, we ensure the victim is not older (or different)
   * than the process we targeted in userspace.
   */
  if (min_start_time_ns != 0) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 start_time = BPF_CORE_READ(task, start_time);
    
    // In some kernel versions/configs this might be slightly off due to boot time nuances,
    // so we usually check if the process started *after* our detailed knowledge,
    // or we can expect exact match if we trust /proc/pid/stat precision.
    // For this PoC, Strict Equality is safest for identity.
    if (start_time != min_start_time_ns) {
        return 0;
    }
  }
  
  // Try to send signal to the thread group (process)
  long ret = bpf_send_signal(SIGKILL);
  if (ret != 0) {
      // Fallback: send to the specific thread if process-wide signaling fails
      bpf_send_signal_thread(SIGKILL);
  }

  // Mark as seen
  killed = true;

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  event->complete = true;
  gadget_submit_buf(ctx, &events, event, sizeof(*event));
  return 0;
}

SEC("tracepoint/sched/sched_switch")
int tracepoint__sched_switch(void *ctx) {
  return kill_process(ctx);
}

SEC("raw_tracepoint/sys_enter")
int tracepoint__sys_enter(void *ctx) {
  return kill_process(ctx);
}

char LICENSE[] SEC("license") = "GPL";
