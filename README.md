# Emulate PinePhone with Unicorn Emulator

We're porting a new operating system ([Apache NuttX RTOS](https://lupyuen.github.io/articles/what)) to [Pine64 PinePhone](https://wiki.pine64.org/index.php/PinePhone). And I wondered...

_To make PinePhone testing easier..._

_Can we emulate Arm64 PinePhone with [Unicorn Emulator](https://www.unicorn-engine.org/)?_

Let's find out! We'll call the [Unicorn Emulator](https://www.unicorn-engine.org/) in Rust (instead of C).

(Because I'm too old to write meticulous C... But I'm OK to get nagged by Rust Compiler if I miss something!)

We begin by emulating simple Arm64 Machine Code...

# Emulate Arm64 Machine Code

![Emulate Arm64 Machine Code](https://lupyuen.github.io/images/unicorn-code.png)

Suppose we wish to emulate some Arm64 Machine Code...

https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs#L7-L8

Here's our Rust Program that calls Unicorn Emulator to emulate the Arm64 Machine Code...

https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs#L1-L55

We add `unicorn-engine` to [Cargo.toml](Cargo.toml)...

https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/Cargo.toml#L8-L9

And we run our Rust Program...

```text
→ cargo run --verbose
  Fresh cc v1.0.79
  Fresh cmake v0.1.49
  Fresh pkg-config v0.3.26
  Fresh bitflags v1.3.2
  Fresh libc v0.2.139
  Fresh unicorn-engine v2.0.1
  Fresh pinephone-emulator v0.1.0
Finished dev [unoptimized + debuginfo] target(s) in 0.08s
  Running `target/debug/pinephone-emulator`
```

Our Rust Program works OK for emulating Arm64 Memory and Arm64 Registers.

Let's talk about Arm64 Memory-Mapped Input / Output...

# Memory Access Hook for Arm64 Emulation

![Memory Access Hook for Arm64 Emulation](https://lupyuen.github.io/images/unicorn-code2.png)

_How will we emulate Arm64 Memory-Mapped Input / Output?_

Unicorn Emulator lets us attach hooks to Emulate Memory Access.

Here's a Hook Function for Memory Access...

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L83-L95

Our Hook Function prints all Read / Write Access to Emulated Arm64 Memory.

[(Return value is unused)](https://github.com/unicorn-engine/unicorn/blob/master/qemu/accel/tcg/cputlb.c#L2004-L2005)

This is how we attach the Hook Function to the Unicorn Emulator...

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L59-L74

When we run our Rust Program, we see the Read and Write Memory Accesses made by our [Emulated Arm64 Code](https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs#L7-L8)...

```text
hook_memory: 
  mem_type=WRITE, 
  address=0x10008, 
  size=4, 
  value=0x12345678

hook_memory: 
  mem_type=READ, 
  address=0x10008, 
  size=1, 
  value=0x0
```

This Memory Access Hook Function will be helpful when we emulate Memory-Mapped Input/Output on PinePhone.

(Like for the Allwinner A64 UART Controller)

Unicorn Emulator allows Code Execution Hooks too...

# Code Execution Hook for Arm64 Emulation

TODO: Call Unicorn Emulator to add Code Execution Hooks

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L108-L117

TODO: Add hook

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L52-L57

Output:

```text
hook_code: address=0x10000, size=4
hook_code: address=0x10004, size=4
```

TODO: Emulate special Arm64 instructions

# Block Execution Hooks for Arm64 Emulation

TODO: Call Unicorn Emulator to add Block Execution Hooks

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L97-L106

TODO: Add hook

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L48-L50

Output:

```text
hook_block: address=0x10000, size=8
```

TODO: Trace the flow of Arm64 execution

TODO: Use Unicorn Emulation Hooks to emulate PinePhone's Allwinner A64 UART Controller

TODO: Emulate Apache NuttX NSH Shell on UART Controller

TODO: Emulate PinePhone's Allwinner A64 Display Engine. How to render the emulated graphics: Use Web Browser + WebAssembly + Unicorn.js? Will framebuffer emulation be slow?

TODO: Emulate Interrupts

TODO: Emulate Multiple CPUs

TODO: Emulate Memory Protection

TODO: What happens when we run [Apache NuttX RTOS for PinePhone](nuttx) in Unicorn Emulator?

```rust
// Arm64 Memory Address where emulation starts
const ADDRESS: u64 = 0x40080000;

// Arm64 Machine Code for the above address
let arm64_code = include_bytes!("../nuttx/nuttx.bin");
```

Here's the output...

```text
hook_block:  address=0x40080000, size=8
hook_code:   address=0x40080000, size=4
hook_code:   address=0x40080004, size=4
hook_block:  address=0x40080040, size=4
hook_code:   address=0x40080040, size=4
hook_block:  address=0x40080044, size=12
hook_code:   address=0x40080044, size=4
hook_memory: address=0x400801a8, size=8, mem_type=READ, value=0x0
hook_code:   address=0x40080048, size=4
hook_memory: address=0x400801b0, size=8, mem_type=READ, value=0x0
hook_code:   address=0x4008004c, size=4
hook_block:  address=0x40080118, size=16
hook_code:   address=0x40080118, size=4
hook_code:   address=0x4008011c, size=4
hook_code:   address=0x40080120, size=4
hook_code:   address=0x40080124, size=4
hook_block:  address=0x40080128, size=8
hook_code:   address=0x40080128, size=4
hook_code:   address=0x4008012c, size=4
hook_block:  address=0x40080130, size=8
hook_code:   address=0x40080130, size=4
hook_code:   address=0x40080134, size=4
hook_block:  address=0x4008015c, size=12
hook_code:   address=0x4008015c, size=4
hook_code:   address=0x40080160, size=4
hook_code:   address=0x40080164, size=4
hook_block:  address=0x40080168, size=4
hook_code:   address=0x40080168, size=4
hook_block:  address=0x4008016c, size=8
hook_code:   address=0x4008016c, size=4
hook_code:   address=0x40080170, size=4
hook_block:  address=0x40080174, size=4
hook_code:   address=0x40080174, size=4
hook_block:  address=0x40080178, size=8
hook_code:   address=0x40080178, size=4
hook_code:   address=0x4008017c, size=4
hook_block:  address=0x40080050, size=4
hook_code:   address=0x40080050, size=4
hook_block:  address=0x400801e8, size=4
hook_code:   address=0x400801e8, size=4
hook_block:  address=0x40080054, size=12
hook_code:   address=0x40080054, size=4
hook_code:   address=0x40080058, size=4
hook_memory: address=0x400801b8, size=8, mem_type=READ, value=0x0
hook_code:   address=0x4008005c, size=4
hook_block:  address=0x40080180, size=12
hook_code:   address=0x40080180, size=4
hook_memory: address=0x400ab000, size=1, mem_type=READ, value=0x0
hook_code:   address=0x40080184, size=4
hook_code:   address=0x40080188, size=4
hook_block:  address=0x4008018c, size=8
hook_code:   address=0x4008018c, size=4
hook_memory: address=0x400c3ff0, size=8, mem_type=WRITE, value=0x0
hook_memory: address=0x400c3ff8, size=8, mem_type=WRITE, value=0x40080060
hook_code:   address=0x40080190, size=4
hook_block:  address=0x400801f0, size=16
hook_code:   address=0x400801f0, size=4
hook_memory: address=0x40080208, size=8, mem_type=READ, value=0x0
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ_UNMAPPED, value=0x0
thread 'main' panicked at 'assertion failed: `(left == right)`
  left: `Ok(29523968)`,
 right: `Ok(120)`', src/main.rs:74:5
```
