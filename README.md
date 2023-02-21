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

![Code Execution Hook for Arm64 Emulation](https://lupyuen.github.io/images/unicorn-code3.png)

_Can we intercept every Arm64 Instruction that will be emulated?_

Yep we can call Unicorn Emulator to add a Code Execution Hook.

Here's a sample Hook Function that will be called for every Arm64 Instruction...

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L108-L117

And this is how we call Unicorn Emulator to add the above Hook Function...

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L52-L57

When we run our Rust Program, we see the Address of every Arm64 Instruction emulated (and its size)...

```text
hook_code: address=0x10000, size=4
hook_code: address=0x10004, size=4
```

We might use this to emulate special Arm64 Instructions.

If we don't need to intercept every single instruction, try the Block Execution Hook...

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

# What is a Block of Arm64 Instructions?

TODO

```text
SECTION_FUNC(text, up_lowputc)
    ldr   x15, =UART0_BASE_ADDRESS
    400801f0:	580000cf 	ldr	x15, 40080208 <up_lowputc+0x18>
/private/tmp/nuttx/nuttx/arch/arm64/src/chip/a64_lowputc.S:89
    early_uart_ready x15, w2
    400801f4:	794029e2 	ldrh	w2, [x15, #20]
    400801f8:	721b005f 	tst	w2, #0x20
    400801fc:	54ffffc0 	b.eq	400801f4 <up_lowputc+0x4>  // b.none
/private/tmp/nuttx/nuttx/arch/arm64/src/chip/a64_lowputc.S:90
    early_uart_transmit x15, w0
    40080200:	390001e0 	strb	w0, [x15]
/private/tmp/nuttx/nuttx/arch/arm64/src/chip/a64_lowputc.S:91
    ret
    40080204:	d65f03c0 	ret
```

[(Source)](nuttx/nuttx.S)

Output:

```text
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0
hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0
hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/cd030954c2ace4cf0207872f275abc3ffb7343c6/README.md#block-execution-hooks-for-arm64-emulation)

# Unmapped Memory in Unicorn Emulator

TODO

```text
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ_UNMAPPED, value=0x0
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/b842358ba457b67ffa9f4c1a362b0386cfd97c4a/README.md#block-execution-hooks-for-arm64-emulation)

Here's how we map the memory...

https://github.com/lupyuen/pinephone-emulator/blob/cd030954c2ace4cf0207872f275abc3ffb7343c6/src/main.rs#L26-L32

# Run Apache NuttX RTOS in Unicorn Emulator

TODO: What happens when we run [Apache NuttX RTOS for PinePhone](nuttx) in Unicorn Emulator?

https://github.com/lupyuen/pinephone-emulator/blob/cd030954c2ace4cf0207872f275abc3ffb7343c6/src/main.rs#L6-L32

Unicorn Emulator hangs, waiting forever for UART Controller to be ready...

# Unicorn Emulator Waits Forever for UART Controller Ready

TODO: Here's the output...

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
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0
hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0

hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0
```

TODO: Loops forever waiting for UART Controller to be ready at `0x01c2` `8014`. Need to simulate UART Controller Ready.

```text
SECTION_FUNC(text, up_lowputc)
    ldr   x15, =UART0_BASE_ADDRESS
    400801f0:	580000cf 	ldr	x15, 40080208 <up_lowputc+0x18>
/private/tmp/nuttx/nuttx/arch/arm64/src/chip/a64_lowputc.S:89
    early_uart_ready x15, w2
    400801f4:	794029e2 	ldrh	w2, [x15, #20]
    400801f8:	721b005f 	tst	w2, #0x20
    400801fc:	54ffffc0 	b.eq	400801f4 <up_lowputc+0x4>  // b.none
/private/tmp/nuttx/nuttx/arch/arm64/src/chip/a64_lowputc.S:90
    early_uart_transmit x15, w0
    40080200:	390001e0 	strb	w0, [x15]
/private/tmp/nuttx/nuttx/arch/arm64/src/chip/a64_lowputc.S:91
    ret
    40080204:	d65f03c0 	ret
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/a1fb82d829856d86d6845c477709c2be24373aca/nuttx/nuttx.S#L3398-L3411)

According to the Allwinner A64 Doc...

-   ["Wait To Transmit"](https://lupyuen.github.io/articles/serial#wait-to-transmit)

`0x01c2` `8014` is the UART Line Status Register (UART_LSR) at Offset 0x14.

Bit 5 needs to be set to 1 to indicate that the UART Transmit FIFO is ready, like this...

https://github.com/lupyuen/pinephone-emulator/blob/6dd4c932fbc503e73c4fb842b236c2f8160195d6/src/main.rs#L40-L44

Unicorn Emulator now continues execution to `memset`...

```text
hook_code:   address=0x40089338, size=4
hook_code:   address=0x4008933c, size=4
hook_block:  address=0x40089328, size=8
hook_code:   address=0x40089328, size=4
hook_code:   address=0x4008932c, size=4
hook_block:  address=0x40089334, size=12
hook_code:   address=0x40089334, size=4
hook_memory: address=0x400b6a52, size=1, mem_type=WRITE, value=0x0

hook_code:   address=0x40089338, size=4
hook_code:   address=0x4008933c, size=4
hook_block:  address=0x40089328, size=8
hook_code:   address=0x40089328, size=4
hook_code:   address=0x4008932c, size=4
hook_block:  address=0x40089334, size=12
hook_code:   address=0x40089334, size=4
hook_memory: address=0x400b6a53, size=1, mem_type=WRITE, value=0x0

hook_code:   address=0x40089338, size=4
hook_code:   address=0x4008933c, size=4
hook_block:  address=0x40089328, size=8
hook_code:   address=0x40089328, size=4
hook_code:   address=0x4008932c, size=4
hook_block:  address=0x40089334, size=12
hook_code:   address=0x40089334, size=4
hook_memory: address=0x400b6a54, size=1, mem_type=WRITE, value=0x0
```

Then Unicorn Emulator halts...

```text
hook_block:  address=0x40080cec, size=16
hook_code:   address=0x40080cec, size=4
hook_memory: address=0x400c3f90, size=8, mem_type=READ, value=0x0
hook_memory: address=0x400c3f98, size=8, mem_type=READ, value=0x0
hook_code:   address=0x40080cf0, size=4
hook_memory: address=0x400c3fa0, size=8, mem_type=READ, value=0x0
hook_code:   address=0x40080cf4, size=4
hook_memory: address=0x400c3f80, size=8, mem_type=READ, value=0x0
hook_memory: address=0x400c3f88, size=8, mem_type=READ, value=0x0
hook_code:   address=0x40080cf8, size=4
hook_block:  address=0x40080eb0, size=12
hook_code:   address=0x40080eb0, size=4
hook_code:   address=0x40080eb4, size=4
hook_code:   address=0x40080eb8, size=4
hook_block:  address=0x40080ebc, size=16
hook_code:   address=0x40080ebc, size=4
hook_code:   address=0x40080ec0, size=4
hook_code:   address=0x40080ec4, size=4
hook_code:   address=0x40080ec8, size=4
hook_block:  address=0x40080ecc, size=16
hook_code:   address=0x40080ecc, size=4
hook_code:   address=0x40080ed0, size=4
hook_code:   address=0x40080ed4, size=4
hook_code:   address=0x40080ed8, size=4
hook_block:  address=0x40080edc, size=12
hook_code:   address=0x40080edc, size=4
hook_code:   address=0x40080ee0, size=4
hook_code:   address=0x40080ee4, size=4
hook_block:  address=0x40080ee8, size=4
hook_code:   address=0x40080ee8, size=4
hook_block:  address=0x40080eec, size=16
hook_code:   address=0x40080eec, size=4
hook_code:   address=0x40080ef0, size=4
hook_code:   address=0x40080ef4, size=4
hook_code:   address=0x40080ef8, size=4
thread 'main' panicked at 'halted emulation: EXCEPTION', src/main.rs:85:7
```

Unicorn Emulator halts at the MMU / EL1 code at `0x4008` `0ef8`...

```text
/private/tmp/nuttx/nuttx/arch/arm64/src/common/arm64_mmu.c:544
  write_sysreg((value | SCTLR_M_BIT | SCTLR_C_BIT), sctlr_el1);
    40080ef0:	d28000a1 	mov	x1, #0x5                   	// #5
    40080ef4:	aa010000 	orr	x0, x0, x1
    40080ef8:	d5181000 	msr	sctlr_el1, x0
```

TODO: Why did MSR fail with an Exception?

Here's the context...

```text
/private/tmp/nuttx/nuttx/arch/arm64/src/common/arm64_mmu.c:516
  for (index = 0; index < mmu_nxrt_config.num_regions; index++)
    40080eb0:	9100a273 	add	x19, x19, #0x28
    40080eb4:	71000694 	subs	w20, w20, #0x1
    40080eb8:	54ffff01 	b.ne	40080e98 <arm64_mmu_init+0x48>  // b.any
enable_mmu_el1():
/private/tmp/nuttx/nuttx/arch/arm64/src/common/arm64_mmu.c:533
  write_sysreg(MEMORY_ATTRIBUTES, mair_el1);
    40080ebc:	d2808000 	mov	x0, #0x400                 	// #1024
    40080ec0:	f2a88180 	movk	x0, #0x440c, lsl #16
    40080ec4:	f2c01fe0 	movk	x0, #0xff, lsl #32
    40080ec8:	d518a200 	msr	mair_el1, x0
/private/tmp/nuttx/nuttx/arch/arm64/src/common/arm64_mmu.c:534
  write_sysreg(get_tcr(1), tcr_el1);
    40080ecc:	d286a380 	mov	x0, #0x351c                	// #13596
    40080ed0:	f2a01000 	movk	x0, #0x80, lsl #16
    40080ed4:	f2c00020 	movk	x0, #0x1, lsl #32
    40080ed8:	d5182040 	msr	tcr_el1, x0
/private/tmp/nuttx/nuttx/arch/arm64/src/common/arm64_mmu.c:535
  write_sysreg(((uint64_t)base_xlat_table), ttbr0_el1);
    40080edc:	d00001a0 	adrp	x0, 400b6000 <g_uart1port>
    40080ee0:	91200000 	add	x0, x0, #0x800
    40080ee4:	d5182000 	msr	ttbr0_el1, x0
arm64_isb():
/private/tmp/nuttx/nuttx/arch/arm64/src/common/barriers.h:58
  __asm__ volatile ("isb" : : : "memory");
    40080ee8:	d5033fdf 	isb
enable_mmu_el1():
/private/tmp/nuttx/nuttx/arch/arm64/src/common/arm64_mmu.c:543
  value = read_sysreg(sctlr_el1);
    40080eec:	d5381000 	mrs	x0, sctlr_el1
/private/tmp/nuttx/nuttx/arch/arm64/src/common/arm64_mmu.c:544
  write_sysreg((value | SCTLR_M_BIT | SCTLR_C_BIT), sctlr_el1);
    40080ef0:	d28000a1 	mov	x1, #0x5                   	// #5
    40080ef4:	aa010000 	orr	x0, x0, x1
    40080ef8:	d5181000 	msr	sctlr_el1, x0
arm64_isb():
/private/tmp/nuttx/nuttx/arch/arm64/src/common/barriers.h:58
    40080efc:	d5033fdf 	isb
arm64_mmu_init():
/private/tmp/nuttx/nuttx/arch/arm64/src/common/arm64_mmu.c:623

  enable_mmu_el1(flags);
```

TODO: Dump the Exception Registers

TODO: Trace the exception in the debugger. Set a breakpoint at `cpu_aarch64_init()` in...

```text
$HOME/.cargo/registry/src/github.com-1ecc6299db9ec823/unicorn-engine-2.0.1/qemu/target/arm/cpu64.c
```

TODO: Emulate the special Arm64 Instructions 

# TODO

TODO: Use Unicorn Emulation Hooks to emulate PinePhone's Allwinner A64 UART Controller

TODO: Emulate Apache NuttX NSH Shell on UART Controller

TODO: Emulate PinePhone's Allwinner A64 Display Engine. How to render the emulated graphics: Use Web Browser + WebAssembly + Unicorn.js? Will framebuffer emulation be slow?

TODO: Emulate Interrupts

TODO: Emulate Multiple CPUs

TODO: Emulate Memory Protection
