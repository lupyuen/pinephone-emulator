# Unicorn Emulator for Apache NuttX RTOS on Avaota-A1 Arm64 SBC

Read the articles...

-   ["(Possibly) Emulate PinePhone with Unicorn Emulator"](https://lupyuen.github.io/articles/unicorn)

-   ["(Clickable) Call Graph for Apache NuttX Real-Time Operating System"](https://lupyuen.github.io/articles/unicorn2)

# TODO

Unicorn is stuck at sys_call0. Is syscall supported in Unicorn?

```bash
hook_block:  address=0x40806d4c, size=04, sched_unlock, sched/sched/sched_unlock.c:90:18
call_graph:  nxsched_merge_pending --> sched_unlock
call_graph:  click nxsched_merge_pending href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_mergepending.c#L84" "sched/sched/sched_mergepending.c " _blank
hook_block:  address=0x40806d50, size=08, sched_unlock, sched/sched/sched_unlock.c:92:19
hook_block:  address=0x40806d58, size=08, sys_call0, arch/arm64/include/syscall.h:152:21
call_graph:  sched_unlock --> sys_call0
call_graph:  click sched_unlock href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_unlock.c#L89" "sched/sched/sched_unlock.c " _blank
err=Err(EXCEPTION)
PC=0x40806d60
WARNING: Your register accessing on id 290 is deprecated and will get UC_ERR_ARG in the future release (2.2.0) because the accessing is either no-op or not defined. If you believe the register should be implemented or there is a bug, please submit an issue to https://github.com/unicorn-engine/unicorn. Set UC_IGNORE_REG_BREAK=1 to ignore this warning.
CP_REG=Ok(0)
ESR_EL0=Ok(0)
ESR_EL1=Ok(0)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
call_graph:  sys_call0 --> ***_HALT_***
call_graph:  click sys_call0 href "https://github.com/apache/nuttx/blob/master/arch/arm64/include/syscall.h#L151" "arch/arm64/include/syscall.h " _blank
```
