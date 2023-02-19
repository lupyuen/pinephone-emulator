# Emulate PinePhone with Unicorn Emulator

_Can we emulate Arm64 PinePhone with [Unicorn Emulator](https://www.unicorn-engine.org/)?_

Let's find out!

# Emulate Arm64 Machine Code

Here's a simple Rust program that calls Unicorn Emulator to emuate some Arm64 Machine Code...

https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs#L1-L55

This works OK for manipulating Arm64 Registers.

# Hooks for Arm64 Emulation

TODO: Call Unicorn Emulator to add Code Emulation Hooks

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L1-L117

Output:

```text
hook_block: address=0x10000, size=8
hook_code: address=0x10000, size=4
hook_memory: mem_type=WRITE, address=0x10008, size=4, value=0x12345678
hook_code: address=0x10004, size=4
hook_memory: mem_type=READ, address=0x10008, size=1, value=0x0
```

TODO: What happens when we run Apache NuttX RTOS for PinePhone?

TODO: Use Unicorn Emulation Hooks to emulate PinePhone's Allwinner A64 UART Controller

TODO: Emulate Apache NuttX NSH Shell on UART Controller
