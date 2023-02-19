use unicorn_engine::{Unicorn, RegisterARM64};
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission};

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

    // memory address where emulation starts
    const ADDRESS: u64 = 0x10000;

    // map 2MB memory for this emulation
    emu.mem_map(
        ADDRESS,
        2 * 1024 * 1024,
        Permission::ALL
    ).expect("failed to map code page");

    // write machine code to be emulated to memory
    emu.mem_write(
        ADDRESS, 
        &arm64_code
    ).expect("failed to write instructions");

    // Register Values
    const X11: u64 = 0x12345678;    // X11 register
    const X13: u64 = 0x10000 + 0x8; // X13 register
    const X15: u64 = 0x33;          // X15 register
    
    // initialize machine registers
    emu.reg_write(RegisterARM64::X11, X11)
        .expect("failed to set X11");
    emu.reg_write(RegisterARM64::X13, X13)
        .expect("failed to set X13");
    emu.reg_write(RegisterARM64::X15, X15)
        .expect("failed to set X15");

    // tracing all basic blocks with customized callback
    let _ = emu.add_block_hook(hook_block)
        .expect("failed to add block hook");

    // tracing one instruction at ADDRESS with customized callback
    let _ = emu.add_code_hook(
        ADDRESS, 
        ADDRESS, 
        hook_code  // Hook Function for Code Emulation
    ).expect("failed to add code hook");

    // Add Memory Hook
    let _ = emu.add_mem_hook(
        HookType::MEM_ALL, 
        0,
        u64::MAX,
        hook_memory
    ).expect("failed to add memory hook");

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
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

// Hook Function for Block Emulation
fn hook_block(_: &mut Unicorn<()>, address: u64, size: u32) {
    println!("hook_block: address={:#x}, size={:?}", address, size);
}

// Hook Function for Code Emulation
fn hook_code(_: &mut Unicorn<()>, address: u64, size: u32) {
    println!("hook_code: address={:#x}, size={:?}", address, size);
}

// Hook Function for Memory Emulation
fn hook_memory(
    _: &mut Unicorn<()>,
    mem_type: MemType,
    address: u64,
    size: usize,
    value: i64
) -> bool {
    println!("hook_memory: mem_type={:?}, address={:#x}, size={:?}, value={:#x}", mem_type, address, size, value);
    true
}
