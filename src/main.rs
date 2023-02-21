use unicorn_engine::{Unicorn, RegisterARM64};
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission};

/// Emulate some Arm64 Machine Code
fn main() {
    // Arm64 Memory Address where emulation starts
    const ADDRESS: u64 = 0x4008_0000;

    // Arm64 Machine Code for the above address
    let arm64_code = include_bytes!("../nuttx/nuttx.bin");

    // Initialize emulator in Arm64 mode
    let mut unicorn = Unicorn::new(
        Arch::ARM64,
        Mode::LITTLE_ENDIAN
    ).expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    // Map 128 MB Executable Memory at the above address for Arm64 Machine Code
    emu.mem_map(
        ADDRESS,            // Address
        128 * 1024 * 1024,  // Size
        Permission::ALL     // Read, Write and Execute Access
    ).expect("failed to map code page");

    // Map 512 MB Read/Write Memory at 0x0000 0000 for
    // Memory-Mapped I/O by Allwinner A64 Peripherals
    // https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/hardware/a64_memorymap.h#L33-L51
    emu.mem_map(
        0x0000_0000,        // Address
        512 * 1024 * 1024,  // Size
        Permission::READ | Permission::WRITE  // Read and Write Access
    ).expect("failed to map memory mapped I/O");

    // Write Arm64 Machine Code to emulated Executable Memory
    emu.mem_write(
        ADDRESS, 
        arm64_code
    ).expect("failed to write instructions");

    // Allwinner A64 UART Line Status Register (UART_LSR) at Offset 0x14.
    // To indicate that the UART Transmit FIFO is ready:
    // Set Bit 5 to 1.
    emu.mem_write(0x01c2_8014, &[0b10_0000])
        .expect("failed to set UART_LSR");

    // Register Values
    const X11: u64 = 0x12345678;    // X11 register
    const X13: u64 = 0x10000 + 0x8; // X13 register
    const X15: u64 = 0x33;          // X15 register
    
    // Initialize machine registers
    emu.reg_write(RegisterARM64::X11, X11)
        .expect("failed to set X11");
    emu.reg_write(RegisterARM64::X13, X13)
        .expect("failed to set X13");
    emu.reg_write(RegisterARM64::X15, X15)
        .expect("failed to set X15");

    // Add Hook for emulating each Basic Block of Arm64 Instructions
    let _ = emu.add_block_hook(hook_block)
        .expect("failed to add block hook");

    // Add Hook for emulating each Arm64 Instruction
    let _ = emu.add_code_hook(
        ADDRESS,  // Begin Address
        ADDRESS + arm64_code.len() as u64,  // End Address
        hook_code  // Hook Function for Code Emulation
    ).expect("failed to add code hook");

    // Add Hook for Arm64 Memory Access
    let _ = emu.add_mem_hook(
        HookType::MEM_ALL, 
        0,
        u64::MAX,
        hook_memory
    ).expect("failed to add memory hook");

    // Emulate machine code in infinite time (last param = 0),
    // or when all code has completed
    let err = emu.emu_start(
        ADDRESS,
        ADDRESS + arm64_code.len() as u64,
        0, // Previously: 10 * SECOND_SCALE,
        0  // Previously: 1000
    );

    // Print the error
    println!("err={:?}", err);
    println!("CP_REG={:?}",  emu.reg_read(RegisterARM64::CP_REG));
    println!("ESR_EL0={:?}", emu.reg_read(RegisterARM64::ESR_EL0));
    println!("ESR_EL1={:?}", emu.reg_read(RegisterARM64::ESR_EL1));
    println!("ESR_EL2={:?}", emu.reg_read(RegisterARM64::ESR_EL2));
    println!("ESR_EL3={:?}", emu.reg_read(RegisterARM64::ESR_EL3));
}

// Hook Function for Memory Access.
// Called once for every Arm64 Memory Access.
fn hook_memory(
    _: &mut Unicorn<()>,  // Emulator
    mem_type: MemType,    // Read or Write Access
    address: u64,  // Accessed Address
    size: usize,   // Number of bytes accessed
    value: i64     // Read / Write Value
) -> bool {
    // TODO: Simulate Memory-Mapped Input/Output (UART Controller)
    // println!("hook_memory: address={:#010x}, size={:?}, mem_type={:?}, value={:#x}", address, size, mem_type, value);
    true
}

// Hook Function for Block Emulation.
// Called once for each Basic Block of Arm64 Instructions.
fn hook_block(
    _: &mut Unicorn<()>,  // Emulator
    address: u64,  // Block Address
    size: u32      // Block Size
) {
    // TODO: Trace the flow of emulated code
    println!("hook_block:  address={:#010x}, size={:?}", address, size);
}

// Hook Function for Code Emulation.
// Called once for each Arm64 Instruction.
fn hook_code(
    _: &mut Unicorn<()>,  // Emulator
    address: u64,  // Instruction Address
    size: u32      // Instruction Size
) {
    // TODO: Handle special Arm64 Instructions
    // println!("hook_code:   address={:#010x}, size={:?}", address, size);
}
