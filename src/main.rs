#[macro_use]
extern crate lazy_static;

use unicorn_engine::{Unicorn, RegisterARM64};
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission};
use std::rc::Rc;
use std::cell::RefCell;

/// ELF File for mapping Addresses to Function Names and Filenames
const ELF_FILENAME: &str = "nuttx/nuttx";

/// Emulate some Arm64 Machine Code
fn main() {
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
    print!("hook_block:  address={:#010x}, size={:02}", address, size);

    // Print the Function Name
    let function = map_address_to_function(address);
    if let Some(ref name) = function {
        print!(", {}", name);
    }

    // Print the Source Filename
    let loc = map_address_to_location(address);
    if let Some((ref file, line, col)) = loc {
        let file = file.clone().unwrap_or("".to_string());
        let line = line.unwrap_or(0);
        let col = col.unwrap_or(0);
        print!(", {}:{}:{}", file, line, col);
    }
    println!();

    // Print the Call Graph
    call_graph(address, size, function, loc);
}

/// Hook Function for Code Emulation.
/// Called once for each Arm64 Instruction.
fn hook_code(
    _: &mut Unicorn<()>,  // Emulator
    address: u64,  // Instruction Address
    _size: u32     // Instruction Size
) {
    // Ignore the memset() loop. TODO: Read the ELF Symbol Table to get address of memset().
    if address >= 0x4008_9328 && address <= 0x4008_933c { return; }

    // TODO: Handle special Arm64 Instructions
    // println!("hook_code:   address={:#010x}, size={:?}", address, _size);
}

/// Map the Arm64 Code Address to the Function Name by looking up the ELF Context
fn map_address_to_function(
    address: u64       // Code Address
) -> Option<String> {  // Function Name
    // Lookup the Arm64 Code Address in the ELF Context
    let context = ELF_CONTEXT.context.borrow();
    let mut frames = context.find_frames(address)
        .expect("failed to find frames");

    // Return the Function Name
    if let Some(frame) = frames.next().unwrap() {
        if let Some(func) = frame.function {
            if let Ok(name) = func.raw_name() {
                let s = String::from(name);
                return Some(s);
            }
        }    
    }
    None
}

/// Map the Arm64 Code Address to the Source Filename, Line and Column
fn map_address_to_location(
    address: u64     // Code Address
) -> Option<(        // Returns...
    Option<String>,  // Filename
    Option<u32>,     // Line
    Option<u32>      // Column
)> {
    // Lookup the Arm64 Code Address in the ELF Context
    let context = ELF_CONTEXT.context.borrow();
    let loc = context.find_location(address)
        .expect("failed to find location");

    // Return the Filename, Line and Column
    if let Some(loc) = loc {
        if let Some(file) = loc.file {
            let s = String::from(file)
                .replace("/private/tmp/nuttx/nuttx/", "");
            Some((Some(s), loc.line, loc.column))
        } else {
            Some((None, loc.line, loc.column))
        }
    } else {
        None
    }
}

/// Print the Mermaid.js Call Graph for this Function Call
fn call_graph(
    address: u64,  // Code Address
    size: u32,     // Size of Code Block
    function: Option<String>,  // Function Name
    loc: Option<(        // Source Location
        Option<String>,  // Filename
        Option<u32>,     // Line
        Option<u32>      // Column
    )>
) {
    // Get the Function Name
    let Some(fname) = function
        else { return; };

    // Unsafe because `LAST_FNAME` is a Static Mutable
    unsafe {
        // Skip we are still in the same Function
        static mut LAST_FNAME: String = String::new();
        if fname.eq(&LAST_FNAME) { return; }

        // Print the Call Flow
        if LAST_FNAME.len() > 0 {
            println!("call_graph:  {} -> {}", LAST_FNAME, fname);
        }
        LAST_FNAME = fname;    
    }
}

lazy_static! {
    /// ELF Context for mapping Addresses to Function Names and Filenames
    static ref ELF_CONTEXT: ElfContext = {
        // Open the ELF File
        let path = std::path::PathBuf::from(ELF_FILENAME);
        let file_data = std::fs::read(path)
            .expect("failed to read ELF");
        let slice = file_data.as_slice();

        // Parse the ELF File
        let obj = addr2line::object::read::File::parse(slice)
            .expect("failed to parse ELF");
        let context = addr2line::Context::new(&obj)
            .expect("failed to parse debug info");
   
        // Set the ELF Context
        ElfContext {
            context: RefCell::new(context),
        }
    };
}

/// Wrapper for ELF Context. Needed for `lazy_static`
struct ElfContext {
    context: RefCell<
        addr2line::Context<
            gimli::EndianReader<
                gimli::RunTimeEndian, 
                Rc<[u8]>  // Doesn't implement Send / Sync
            >
        >
    >
}

/// Send and Sync for ELF Context. Needed for `lazy_static`
unsafe impl Send for ElfContext {}
unsafe impl Sync for ElfContext {}
