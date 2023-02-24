use std::process::exit;

use unicorn_engine::{Unicorn, RegisterARM64};
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission};
use elf::ElfBytes;
use elf::endian::AnyEndian;

/// Emulate some Arm64 Machine Code
fn main() {
    // Load the Symbol Table from the ELF File
    load_symbol_table("nuttx/nuttx");

    // Arm64 Memory Address where emulation starts
    const ADDRESS: u64 = 0x4008_0000;

    // Arm64 Machine Code for the above address
    let arm64_code = include_bytes!("../nuttx/nuttx.bin");

    // Init Emulator in Arm64 mode
    let mut unicorn = Unicorn::new(
        Arch::ARM64,
        Mode::LITTLE_ENDIAN
    ).expect("failed to init Unicorn");

    // Magical horse mutates to bird
    let emu = &mut unicorn;

    // Map 128 MB Executable Memory at 0x4000 0000 for Arm64 Machine Code
    // https://github.com/apache/nuttx/blob/master/arch/arm64/include/a64/chip.h#L44-L52
    emu.mem_map(
        0x4000_0000,        // Address
        128 * 1024 * 1024,  // Size
        Permission::ALL     // Read, Write and Execute Access
    ).expect("failed to map code page");

    // Map 512 MB Read/Write Memory at 0x0000 0000 for
    // Memory-Mapped I/O by Allwinner A64 Peripherals
    // https://github.com/apache/nuttx/blob/master/arch/arm64/include/a64/chip.h#L44-L52
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
    // https://lupyuen.github.io/articles/serial#wait-to-transmit
    emu.mem_write(
        0x01c2_8014,  // UART Register Address
        &[0b10_0000]  // UART Register Value
    ).expect("failed to set UART_LSR");

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
        HookType::MEM_ALL,  // Intercept Read and Write Accesses
        0,           // Begin Address
        u64::MAX,    // End Address
        hook_memory  // Hook Function
    ).expect("failed to add memory hook");

    // Emulate Arm64 Machine Code
    let err = emu.emu_start(
        ADDRESS,  // Begin Address
        ADDRESS + arm64_code.len() as u64,  // End Address
        0,  // No Timeout
        0   // Unlimited number of instructions
    );

    // Print the Emulator Error
    println!("err={:?}", err);

    // Doesn't work for printing the Exception Registers
    println!("CP_REG={:?}",  emu.reg_read(RegisterARM64::CP_REG));
    println!("ESR_EL0={:?}", emu.reg_read(RegisterARM64::ESR_EL0));
    println!("ESR_EL1={:?}", emu.reg_read(RegisterARM64::ESR_EL1));
    println!("ESR_EL2={:?}", emu.reg_read(RegisterARM64::ESR_EL2));
    println!("ESR_EL3={:?}", emu.reg_read(RegisterARM64::ESR_EL3));
}

/// Hook Function for Memory Access.
/// Called once for every Arm64 Memory Access.
fn hook_memory(
    _: &mut Unicorn<()>,  // Emulator
    mem_type: MemType,    // Read or Write Access
    address: u64,  // Accessed Address
    size: usize,   // Number of bytes accessed
    value: i64     // Write Value
) -> bool {
    // Ignore RAM access, we only intercept Memory-Mapped Input / Output
    if address >= 0x4000_0000 { return true; }
    println!("hook_memory: address={:#010x}, size={:?}, mem_type={:?}, value={:#x}", address, size, mem_type, value);

    // If writing to UART Transmit Holding Register (THR):
    // Print the UART Output
    // https://lupyuen.github.io/articles/serial#transmit-uart
    if address == 0x01c2_8000 {
        println!("uart output: {:?}", value as u8 as char);
    }

    // Always return true, value is unused by caller
    // https://github.com/unicorn-engine/unicorn/blob/dev/docs/FAQ.md#i-cant-recover-from-unmapped-readwrite-even-i-return-true-in-the-hook-why
    true
}

/// Hook Function for Block Emulation.
/// Called once for each Basic Block of Arm64 Instructions.
fn hook_block(
    _: &mut Unicorn<()>,  // Emulator
    address: u64,  // Block Address
    size: u32      // Block Size
) {
    // Ignore the memset() loop. TODO: Read the ELF Symbol Table to get address of memset().
    if address >= 0x4008_9328 && address <= 0x4008_933c { return; }

    // Trace the flow of emulated code
    println!("hook_block:  address={:#010x}, size={:?}", address, size);
}

/// Hook Function for Code Emulation.
/// Called once for each Arm64 Instruction.
fn hook_code(
    _: &mut Unicorn<()>,  // Emulator
    address: u64,  // Instruction Address
    size: u32      // Instruction Size
) {
    // Ignore the memset() loop. TODO: Read the ELF Symbol Table to get address of memset().
    if address >= 0x4008_9328 && address <= 0x4008_933c { return; }

    // TODO: Handle special Arm64 Instructions
    // println!("hook_code:   address={:#010x}, size={:?}", address, size);
}

/// Load the Symbol Table from the ELF File
fn load_symbol_table(filename: &str) {
    let path = std::path::PathBuf::from(filename);
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");
    
    // Find lazy-parsing types for the common ELF sections (we want .dynsym, .dynstr, .hash)
    let common = file.find_common_data().expect("shdrs should parse");
    let symtab = common.symtab.unwrap();
    let strtab = common.symtab_strs.unwrap();

    // Dump the Symbol Table
    println!("symtab.len={:?}", symtab.len());
    for i in 0..symtab.len() {
        // `sym` contains { st_name: 46, st_shndx: 1007, st_info: 0, st_other: 0, st_value: 1074442240, st_size: 0 }
        // TODO: What is `st_shndx`?
        let sym = symtab.get(i).unwrap();
        let st_name = sym.st_name;  // Index of Symbol Name in String Table

        // Get the Symbol Name
        // "$x" means "Start of a sequence of A64 instructions"
        // "$d" means "Start of a sequence of data items (for example, a literal pool)"
        // https://github.com/ARM-software/abi-aa/blob/2020q4/aaelf64/aaelf64.rst#mapping-symbols
        if st_name != 0 {
            let name = strtab.get(st_name as usize).unwrap();
            let value = sym.st_value;
            println!("{}={:#x}", name, value);    
        }
    }
}
