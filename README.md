# pkiller - eBPF Process Killer (Proof of Concept)

**pkiller** is a Proof of Concept (PoC) illustrating how eBPF can be used to delegate process management tasks—specifically sending `SIGKILL`—directly to the kernel.

By offloading the "trigger" logic to the kernel, this tool demonstrates a specific architectural pattern for managing host processes.

## The Architectural Idea vs. The Security Reality

The initial appeal of this approach is obvious: instead of mapping the entire host PID namespace into a container (via `--pid=host`), which exposes every process on the host to the container, we delegate the task to the kernel. The container says "kill PID X", and the kernel handles it.

However, calling this a "security improvement" in its current form would be misleading.

### The Privilege Irony

To run this tool today, your container requires privileges that are arguably more dangerous than the ones we are trying to avoid.

1.  **Loading eBPF**: Requires `CAP_BPF` or, more commonly, `CAP_SYS_ADMIN` (often referred to as "the new root").
2.  **Global Visibility**: To function, this program attaches to global tracepoints (`sched_switch`, `sys_enter`). While `pkiller` *ignores* processes that don't match the target PID, the *capability* to see every context switch and system call entry on the machine is inherent to the permission set required to load it.

**In short:** We are exchanging "Ability to see/kill all processes via /proc" (User Space) for "Ability to run code in the kernel and hook global events" (Kernel Space). In many threat models, the latter is a higher risk.

## Path to Production: What would be required for safe deployment

This PoC demonstrates the *mechanism*, but not the *security controls* needed for production. To make this a true "least privilege" solution, we need to separate the **Actor** from the **Loader**.

This is where platforms like **Inspektor Gadget** shine:

1.  **Signed Gadgets & Policy**: If this eBPF program is packaged as a signed OCI artifact, an improperly privileged user (or compromised container) cannot modify the bytecode, and can only invoke the behavior explicitly exposed by the gadget interface.
2.  **The "Sudo" for BPF**: The goal is to have a privileged agent (Inspektor Gadget) running on the node that has the `CAP_BPF` rights. The user/pod makes a constrained request ("Please run the signed `pkiller` gadget against PID 123").
3.  **True Scoping**: In this model, the requestor needs only need authorization to invoke the gadget with the parameters exposed by its policy interface.

## How It Works

`pkiller` attaches to two high-frequency kernel tracepoints:
1.  `tracepoint/sched/sched_switch`: Triggered whenever the scheduler switches tasks.
2.  `raw_tracepoint/sys_enter`: Triggered whenever a process makes a system call.

> **Note**: Attaching to high-frequency global tracepoints is acceptable for a PoC, but a production implementation would enforce policy at lower-frequency, semantically meaningful hooks (e.g., exec or LSM decision points).

When the target PID triggers either of these events, the eBPF program:
1.  Checks if the PID matches the target `pid_to_kill`.
2.  **Safety Check**: If `min_start_time_ns` is provided, it verifies the process start time (from `task_struct->start_time`) matches the expected value. This prevents killing a new process that reused the PID (PIDs are recycled by the OS).
3.  Checks if the target has already been killed (using a global atomic state).
4.  Calls `bpf_send_signal(SIGKILL)` to terminate the entire thread group (the process) immediately. Start with this Helper to ensure the whole process is targeted.

Note: PID + start_time reduces reuse risk but is still weaker than cgroup- or task-cookie-based identity, which would be preferred in a production design.

## "What if the process never interacts with the kernel?"

A common question is: *will this work if the process is effectively idle or stuck in a tight CPU loop?*

The answer is **yes**, it will still be killed.

*   **System Calls**: Most applications constantly talk to the kernel (reading files, network I/O, writing logs). These are caught by `sys_enter`.
*   **Context Switching**: Even if a process is in a tight `while(1)` loop doing purely user-space math, it does not own the CPU forever. The Linux scheduler enforces time slices. Eventually, the kernel will preempt the process to let others run. This preemption event fires `sched_switch`, allowing our eBPF program to intervene and kill the process.

Therefore, unless the system is completely frozen, the process *must* interact with the kernel scheduling machinery, ensuring the kill signal is delivered.
