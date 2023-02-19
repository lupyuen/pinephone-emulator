# Emulate PinePhone with Unicorn Emulator

_Can we emulate Arm64 PinePhone with [Unicorn Emulator](https://www.unicorn-engine.org/)?_

Let's find out!

Here's a simple Rust program that calls Unicorn Emulator to emuate some Arm64 Machine Code...

https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs#L1-L55

This works OK for manipulating Arm64 Registers.

TODO: Call Unicorn Emulator to add Code Emulation Hooks

TODO: What happens when we run Apache NuttX RTOS for PinePhone?
