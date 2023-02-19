use unicorn_engine::{Unicorn, RegisterARM64};
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission};

/// Emulate some Arm64 Machine Code
fn main() {
    // Arm64 Machine Code
    let arm64_code: Vec<u8> = vec![
        0xab, 0x05, 0x00, 0xb8,  // str  w11, [x13], #0
        0xaf, 0x05, 0x40, 0x38,  // ldrb w15, [x13], #0
    ];

    // Initialize emulator in ARM64 mode
    let mut unicorn = Unicorn::new(
        Arch::ARM64,
        Mode::LITTLE_ENDIAN
    ).expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    // Memory address where emulation starts
    const ADDRESS: u64 = 0x10000;

    // Map 2MB memory for this emulation
    emu.mem_map(
        ADDRESS,          // Address
        2 * 1024 * 1024,  // Size
        Permission::ALL   // Permissions
    ).expect("failed to map code page");

    // Write machine code to be emulated to memory
    emu.mem_write(
        ADDRESS, 
        &arm64_code
    ).expect("failed to write instructions");

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
    let _ = emu.emu_start(
        ADDRESS,
        ADDRESS + arm64_code.len() as u64,
        0, // Previously: 10 * SECOND_SCALE,
        0  // Previously: 1000
    );

    // Read register X15
    assert_eq!(
        emu.reg_read(RegisterARM64::X15),
        Ok(0x78)
    );
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
    println!("hook_memory: mem_type={:?}, address={:#x}, size={:?}, value={:#x}", mem_type, address, size, value);
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
    println!("hook_block: address={:#x}, size={:?}", address, size);
}

// Hook Function for Code Emulation.
// Called once for each Arm64 Instruction.
fn hook_code(
    _: &mut Unicorn<()>,  // Emulator
    address: u64,  // Instruction Address
    size: u32      // Instruction Size
) {
    // TODO: Handle special Arm64 Instructions
    println!("hook_code: address={:#x}, size={:?}", address, size);
}

/* Output:
hook_block: address=0x10000, size=8
hook_code: address=0x10000, size=4
hook_memory: mem_type=WRITE, address=0x10008, size=4, value=0x12345678
hook_code: address=0x10004, size=4
hook_memory: mem_type=READ, address=0x10008, size=1, value=0x0
*/