use core::time;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Mutex;
use std::thread::sleep;
use unicorn_engine::{Unicorn, RegisterARM64};
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission};
use once_cell::sync::Lazy;

/// ELF File for mapping Addresses to Function Names and Filenames
const ELF_FILENAME: &str = "nuttx/nuttx";

/// Memory Space for NuttX Kernel
const KERNEL_SIZE: usize = 0x1000_0000;
static mut kernel_code: [u8; KERNEL_SIZE] = [0; KERNEL_SIZE];

/// UART Base Address
const UART0_BASE_ADDRESS: u64 = 0x900_0000;

/// Emulate some Arm64 Machine Code
fn main() {
    // Test Arm64 MMU
    // test_arm64_mmu(); return;

    // Arm64 Memory Address where emulation starts.
    // Memory Space for NuttX Kernel also begins here.
    const ADDRESS: u64 = 0x4028_0000;

    // Copy NuttX Kernel into the above address
    let kernel = include_bytes!("../nuttx/nuttx.bin");
    unsafe {
        assert!(kernel_code.len() >= kernel.len());
        kernel_code[0..kernel.len()].copy_from_slice(kernel);    
    }

    // Init Emulator in Arm64 mode
    let mut unicorn = Unicorn::new(
        Arch::ARM64,
        Mode::LITTLE_ENDIAN
    ).expect("failed to init Unicorn");

    // Magical horse mutates to bird
    let emu = &mut unicorn;

    // Enable MMU Translation
    // uc_ctl_tlb_mode(uc, UC_TLB_CPU)
    // -> uc_ctl(uc, UC_CTL_WRITE(UC_CTL_TLB_TYPE, 1), (UC_TLB_CPU))
    emu.ctl_tlb_type(unicorn_engine::TlbType::CPU).unwrap();

    // Disable MMU Translation
    // emu.ctl_tlb_type(unicorn_engine::TlbType::VIRTUAL).unwrap();

    // Map 1 GB Read/Write Memory at 0x0000 0000 for Memory-Mapped I/O
    emu.mem_map(
        0x0000_0000,  // Address
        0x4000_0000,  // Size
        Permission::READ | Permission::WRITE  // Read/Write/Execute Access
    ).expect("failed to map memory");

    // Map the NuttX Kernel to 0x4028_0000
    unsafe {
        emu.mem_map_ptr(
            ADDRESS, 
            kernel_code.len(), 
            Permission::READ | Permission::EXEC,
            kernel_code.as_mut_ptr() as _
        ).expect("failed to map kernel");
    }

    // Set QEMU UART to Ready
    emu.mem_write(
        UART0_BASE_ADDRESS + 0x18,  // UART Register Address
        &[0]  // UART Register Value
    ).expect("failed to set UART_LSR");

    // Add Hook for emulating each Basic Block of Arm64 Instructions
    let _ = emu.add_block_hook(1, 0, hook_block)
        .expect("failed to add block hook");

    // Add Hook for emulating each Arm64 Instruction
    let _ = emu.add_code_hook(
        ADDRESS,  // Begin Address
        ADDRESS + KERNEL_SIZE as u64,  // End Address
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
        ADDRESS + KERNEL_SIZE as u64,  // End Address
        0,  // No Timeout
        0   // Unlimited number of instructions
    );

    // Print the Emulator Error
    println!("err={:?}", err);

    // Doesn't work for printing the Exception Registers
    println!("PC=0x{:x}",  emu.reg_read(RegisterARM64::PC).unwrap());
    println!("CP_REG={:?}",  emu.reg_read(RegisterARM64::CP_REG));
    println!("ESR_EL0={:?}", emu.reg_read(RegisterARM64::ESR_EL0));
    println!("ESR_EL1={:?}", emu.reg_read(RegisterARM64::ESR_EL1));
    println!("ESR_EL2={:?}", emu.reg_read(RegisterARM64::ESR_EL2));
    println!("ESR_EL3={:?}", emu.reg_read(RegisterARM64::ESR_EL3));

    // Close the Call Graph
    call_graph(0, 0,  // Address and Size
        Some("***_HALT_***".to_string()), // Function Name
        (None, None, None)  // Function Location
    );
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
    // println!("hook_memory: address={address:#010x}, size={size:02}, mem_type={mem_type:?}, value={value:#x}");

    // If writing to UART Transmit Holding Register (THR):
    // Print the UART Output
    // https://lupyuen.github.io/articles/serial#transmit-uart
    if address == UART0_BASE_ADDRESS {
        // println!("uart output: {:?}", value as u8 as char);
        print!("{}", value as u8 as char);
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

    // Print the Function Name
    let function = map_address_to_function(address);
    if function == Some("a527_copy_overlap".into())
        || function == Some("a527_copy_ramdisk".into())
        || function == Some("arm64_data_initialize".into())
        || function == Some("memcmp".into())
        || function == Some("strcmp".into())
        { return; }
    if function == Some("uart_open".into())
        || function == Some("pl011_receive".into())
        { sleep(time::Duration::from_secs(10)); }

    print!("hook_block:  address={address:#010x}, size={size:02}");
    if let Some(ref name) = function {
        print!(", {name}");
    }

    // Print the Source Filename
    let loc = map_address_to_location(address);
    let (ref file, line, col) = loc;
    let file = file.clone().unwrap_or("".to_string());
    let line = line.unwrap_or(0);
    let col = col.unwrap_or(0);
    println!(", {file}:{line}:{col}");

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
    // println!("hook_code:   address={address:#010x}, size={_size:02}");
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
) -> (               // Returns...
    Option<String>,  // Filename
    Option<u32>,     // Line
    Option<u32>      // Column
) {
    // Lookup the Arm64 Code Address in the ELF Context
    let context = ELF_CONTEXT.context.borrow();
    let loc = context.find_location(address)
        .expect("failed to find location");

    // Return the Filename, Line and Column
    if let Some(loc) = loc {
        if let Some(file) = loc.file {
            let s = String::from(file)
                .replace("/Users/luppy/avaota/nuttx/", "")
                .replace("/private/tmp/250313/nuttx/", "")
                .replace("arch/arm64/src/chip", "arch/arm64/src/qemu");  // TODO: Handle other chips
            (Some(s), loc.line, loc.column)
        } else {
            (None, loc.line, loc.column)
        }
    } else {
        (None, None, None)
    }
}

/// Print the Mermaid Call Graph for this Function Call:
/// cargo run | grep call_graph | cut -c 12-
fn call_graph(
    _address: u64,  // Code Address
    _size: u32,     // Size of Code Block
    function: Option<String>,  // Function Name
    loc: (               // Source Location
        Option<String>,  // Filename
        Option<u32>,     // Line
        Option<u32>      // Column
    )
) {
    // Get the Function Name
    let fname = match function {
        Some(fname) => fname,
        None => map_location_to_function(&loc)
    };

    // Skip if we are still in the same Function
    let mut last_fname = LAST_FNAME.lock().unwrap();
    let mut last_loc = LAST_LOC.lock().unwrap();
    if fname.eq(last_fname.as_str()) { return; }

    // If this function has not been shown too often...
    if can_show_function(&fname) {
        // Print the Call Flow
        if last_fname.is_empty() {            
            println!("call_graph:  flowchart TD");  // Top-Down Flowchart
            println!("call_graph:  START --> {fname}");
        } else {
            // URL looks like https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L541
            let (file, line, _) = last_loc.clone();
            let file = file.unwrap_or("".to_string());
            let line = line.unwrap_or(1) - 1;
            let url = format!("https://github.com/apache/nuttx/blob/master/{file}#L{line}");
            println!("call_graph:  {last_fname} --> {fname}");
            println!("call_graph:  click {last_fname} href \"{url}\" \"{file} \" _blank");
        }
    }

    // Remember the Function Name and Source Location
    *last_fname = fname;
    *last_loc = loc;
}

/// Map a Location to a Function Name.
/// `arch/arm64/src/common/arm64_head.S` becomes `arm64_head`
fn map_location_to_function(
    loc: &(              // Source Location
        Option<String>,  // Filename
        Option<u32>,     // Line
        Option<u32>      // Column
    )
) -> String {
    let s = loc.0.clone().unwrap_or("".to_string());
    let s = s.split('/').last().unwrap();
    let s = s.split('.').next().unwrap();
    String::from(s)
}

/// Return true if this Function has not been shown too often
fn can_show_function(fname: &str) -> bool {
    // Get the Occurrence Count for the Function Name
    let mut map = FUNC_COUNT.lock().unwrap();
    let count = map.get(fname)
        .unwrap_or(&0_usize)
        .clone();

    // Increment the Occurrence Count
    map.insert(fname.to_string(), count + 1);

    // If the Function has appeared too often, don't show it
    count < 8
}

/// ELF Context for mapping Addresses to Function Names and Source Location
static ELF_CONTEXT: Lazy<ElfContext> = Lazy::new(|| {
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
});

/// Wrapper for ELF Context. Needed for `Lazy`
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

/// Send and Sync for ELF Context. Needed for `Lazy`
unsafe impl Send for ElfContext {}
unsafe impl Sync for ElfContext {}

/// Map Function Name to Number of Occurrences
static FUNC_COUNT: Lazy<Mutex<HashMap<String, usize>>> = Lazy::new(||
    HashMap::new().into()
);

/// Last Function Name
static LAST_FNAME: Lazy<Mutex<String>> = Lazy::new(||
    String::new().into()
);

/// Last Source Location
static LAST_LOC: Lazy<Mutex<(Option<String>, Option<u32>, Option<u32>)>> = Lazy::new(||
    (None, None, None).into()
);

/// Unit Test for Arm64 MMU
/// https://github.com/unicorn-engine/unicorn/blob/master/tests/unit/test_arm64.c#L378-L486
fn test_arm64_mmu() {
    /*
     * Not exact the binary, but aarch64-linux-gnu-as generate this code and
     reference sometimes data after ttb0_base.
     * // Read data from physical address
     * ldr X0, =0x40000000
     * ldr X1, [X0]

     * // Initialize translation table control registers
     * ldr X0, =0x180803F20
     * msr TCR_EL1, X0
     * ldr X0, =0xFFFFFFFF
     * msr MAIR_EL1, X0

     * // Set translation table
     * adr X0, ttb0_base
     * msr TTBR0_EL1, X0

     * // Enable caches and the MMU
     * mrs X0, SCTLR_EL1
     * orr X0, X0, #(0x1 << 2) // The C bit (data cache).
     * orr X0, X0, #(0x1 << 12) // The I bit (instruction cache)
     * orr X0, X0, #0x1 // The M bit (MMU).
     * msr SCTLR_EL1, X0
     * dsb SY
     * isb

     * // Read the same memory area through virtual address
     * ldr X0, =0x80000000
     * ldr X2, [X0]
     *
     * // Stop
     * b .
     */
    let arm64_code = [
        0x00, 0x81, 0x00, 0x58, 0x01, 0x00, 0x40, 0xf9, 0x00, 0x81, 0x00, 0x58, 0x40, 0x20, 0x18,
        0xd5, 0x00, 0x81, 0x00, 0x58, 0x00, 0xa2, 0x18, 0xd5, 0x40, 0x7f, 0x00, 0x10, 0x00, 0x20,
        0x18, 0xd5, 0x00, 0x10, 0x38, 0xd5, 0x00, 0x00, 0x7e, 0xb2, 0x00, 0x00, 0x74, 0xb2, 0x00,
        0x00, 0x40, 0xb2, 0x00, 0x10, 0x18, 0xd5, 0x9f, 0x3f, 0x03, 0xd5, 0xdf, 0x3f, 0x03, 0xd5,
        0xe0, 0x7f, 0x00, 0x58, 0x02, 0x00, 0x40, 0xf9, 0x00, 0x00, 0x00, 0x14, 0x1f, 0x20, 0x03,
        0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5,       
    ];

    // Init Emulator in Arm64 mode
    // OK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc));
    let mut unicorn = Unicorn::new(
        Arch::ARM64,
        Mode::LITTLE_ENDIAN
    ).expect("failed to init Unicorn");

    // Magical horse mutates to bird
    let emu = &mut unicorn;

    // Enable MMU Translation
    // OK(uc_ctl_tlb_mode(uc, UC_TLB_CPU));
    emu.ctl_tlb_type(unicorn_engine::TlbType::CPU).unwrap();

    // Map Read/Write/Execute Memory at 0x0000 0000
    // OK(uc_mem_map(uc, 0, 0x2000, UC_PROT_ALL));
    emu.mem_map(
        0,       // Address
        0x2000,  // Size
        Permission::ALL  // Read/Write/Execute Access
    ).expect("failed to map memory");

    // Write Arm64 Machine Code to emulated Executable Memory
    // OK(uc_mem_write(uc, 0, code, sizeof(code) - 1));
    const ADDRESS: u64 = 0;
    emu.mem_write(
        ADDRESS, 
        &arm64_code
    ).expect("failed to write instructions");

    // generate tlb entries
    let mut tlbe: [u8; 8] = [0; 8];
    tlbe[0] = 0x41;
    tlbe[1] = 0x07;
    tlbe[2] = 0;
    tlbe[3] = 0;
    tlbe[4] = 0;
    tlbe[5] = 0;
    tlbe[6] = 0;
    tlbe[7] = 0;
    emu.mem_write(0x1000, &tlbe).unwrap();
    log_tlbe(0x1000, &tlbe);

    tlbe[3] = 0xa0;
    emu.mem_write(0x1008, &tlbe).unwrap();
    log_tlbe(0x1008, &tlbe);

    tlbe[3] = 0x40;
    emu.mem_write(0x1010, &tlbe).unwrap();
    log_tlbe(0x1010, &tlbe);

    tlbe[3] = 0x80;
    emu.mem_write(0x1018, &tlbe).unwrap();
    log_tlbe(0x1018, &tlbe);

    // mentioned data referenced by the asm generated my aarch64-linux-gnu-as
    tlbe[0] = 0x00;
    tlbe[1] = 0x00;
    tlbe[2] = 0x00;
    tlbe[3] = 0x40;

    // OK(uc_mem_write(uc, 0x1020, tlbe, sizeof(tlbe)));
    emu.mem_write(0x1020, &tlbe).unwrap();
    log_tlbe(0x1020, &tlbe);

    tlbe[0] = 0x20;
    tlbe[1] = 0x3f;
    tlbe[2] = 0x80;
    tlbe[3] = 0x80;
    tlbe[4] = 0x1;

    // OK(uc_mem_write(uc, 0x1028, tlbe, sizeof(tlbe)));
    emu.mem_write(0x1028, &tlbe).unwrap();
    log_tlbe(0x1028, &tlbe);

    tlbe[0] = 0xff;
    tlbe[1] = 0xff;
    tlbe[2] = 0xff;
    tlbe[3] = 0xff;
    tlbe[4] = 0x00;

    // OK(uc_mem_write(uc, 0x1030, tlbe, sizeof(tlbe)));
    emu.mem_write(0x1030, &tlbe).unwrap();
    log_tlbe(0x1030, &tlbe);

    tlbe[0] = 0x00;
    tlbe[1] = 0x00;
    tlbe[2] = 0x00;
    tlbe[3] = 0x80;

    // OK(uc_mem_write(uc, 0x1038, tlbe, sizeof(tlbe)));
    emu.mem_write(0x1038, &tlbe).unwrap();
    log_tlbe(0x1038, &tlbe);

    let mut data: [u8; 0x1000] = [0x44; 0x1000];
    let mut data2: [u8; 0x1000] = [0x88; 0x1000];
    let mut data3: [u8; 0x1000] = [0xcc; 0x1000];

    // OK(uc_mem_map_ptr(uc, 0x40000000, 0x1000, UC_PROT_READ, data));
    unsafe {
        emu.mem_map_ptr(0x40000000, 0x1000, Permission::READ, data.as_mut_ptr() as _)
            .unwrap();
        emu.mem_map_ptr(0x80000000, 0x1000, Permission::READ, data2.as_mut_ptr() as _)
            .unwrap();
        emu.mem_map_ptr(0xa0000000, 0x1000, Permission::READ, data3.as_mut_ptr() as _)
            .unwrap();
    }

    // OK(uc_emu_start(uc, 0, 0x44, 0, 0));
    let err = emu.emu_start(0, 0x44, 0, 0);

    // Print the Emulator Error
    println!("\nerr={:?}", err);

    // Read registers X0, X1, X2
    let x0 = emu.reg_read(RegisterARM64::X0).unwrap();
    let x1 = emu.reg_read(RegisterARM64::X1).unwrap();
    let x2 = emu.reg_read(RegisterARM64::X2).unwrap();
    println!("x0=0x{x0:x}");
    println!("x1=0x{x1:x}");
    println!("x2=0x{x2:x}");

    assert!(x0 == 0x80000000);
    assert!(x1 == 0x4444444444444444);
    assert!(x2 == 0x4444444444444444);
}

/// Log the MMU TLB Entry. 0x741 will print:
/// Bit 00-01: PTE_BLOCK_DESC=1
/// Bit 06: PTE_BLOCK_DESC_AP_USER=1
/// Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE=3
/// Bit 10: PTE_BLOCK_DESC_AF=1
fn log_tlbe(address: u64, tlbe: &[u8]) {
    let mut n: u64 = 0;
    tlbe.iter().rev()
        .for_each(|b| n = (n << 8) | *b as u64);
    println!("TLBE @ 0x{address:04x}: 0x{n:016x}");
    println!("addr_pa=0x{:08x}", n & 0xfffff000);
    println!("Bit 00-01: PTE_BLOCK_DESC={}", n & 0b11);
    println!("Bit 06:    PTE_BLOCK_DESC_AP_USER={}", (n >> 6) & 0b1);
    println!("Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE={}", (n >> 8) & 0b11);
    println!("Bit 10:    PTE_BLOCK_DESC_AF={}\n", (n >> 10) & 0b1);
}

/* Disassembly for Arm64 Machine Code:
https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=%22%5Cx00%5Cx81%5Cx00%5Cx58%5Cx01%5Cx00%5Cx40%5Cxf9%5Cx00%5Cx81%5Cx00%5Cx58%5Cx40%5Cx20%5Cx18%5Cxd5%5Cx00%5Cx81%5Cx00%5Cx58%5Cx00%5Cxa2%5Cx18%5Cxd5%5Cx40%5Cx7f%5Cx00%5Cx10%5Cx00%5Cx20%5Cx18%5Cxd5%5Cx00%5Cx10%5Cx38%5Cxd5%5Cx00%5Cx00%5Cx7e%5Cxb2%5Cx00%5Cx00%5Cx74%5Cxb2%5Cx00%5Cx00%5Cx40%5Cxb2%5Cx00%5Cx10%5Cx18%5Cxd5%5Cx9f%5Cx3f%5Cx03%5Cxd5%5Cxdf%5Cx3f%5Cx03%5Cxd5%5Cxe0%5Cx7f%5Cx00%5Cx58%5Cx02%5Cx00%5Cx40%5Cxf9%5Cx00%5Cx00%5Cx00%5Cx14%5Cx1f%5Cx20%5Cx03%5Cxd5%5Cx1f%5Cx20%5Cx03%5Cxd5%5Cx1F%5Cx20%5Cx03%5CxD5%5Cx1F%5Cx20%5Cx03%5CxD5%22&arch=arm64&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly
"\x00\x81\x00\x58\x01\x00\x40\xf9\x00\x81\x00\x58\x40\x20\x18\xd5\x00\x81\x00\x58\x00\xa2\x18\xd5\x40\x7f\x00\x10\x00\x20\x18\xd5\x00\x10\x38\xd5\x00\x00\x7e\xb2\x00\x00\x74\xb2\x00\x00\x40\xb2\x00\x10\x18\xd5\x9f\x3f\x03\xd5\xdf\x3f\x03\xd5\xe0\x7f\x00\x58\x02\x00\x40\xf9\x00\x00\x00\x14\x1f\x20\x03\xd5\x1f\x20\x03\xd5\x1F\x20\x03\xD5\x1F\x20\x03\xD5"

0x0000000000000000:  00 81 00 58    ldr x0, #0x1020
0x0000000000000004:  01 00 40 F9    ldr x1, [x0]
0x0000000000000008:  00 81 00 58    ldr x0, #0x1028
0x000000000000000c:  40 20 18 D5    msr tcr_el1, x0
0x0000000000000010:  00 81 00 58    ldr x0, #0x1030
0x0000000000000014:  00 A2 18 D5    msr mair_el1, x0
0x0000000000000018:  40 7F 00 10    adr x0, #0x1000
0x000000000000001c:  00 20 18 D5    msr ttbr0_el1, x0
0x0000000000000020:  00 10 38 D5    mrs x0, sctlr_el1
0x0000000000000024:  00 00 7E B2    orr x0, x0, #4
0x0000000000000028:  00 00 74 B2    orr x0, x0, #0x1000
0x000000000000002c:  00 00 40 B2    orr x0, x0, #1
0x0000000000000030:  00 10 18 D5    msr sctlr_el1, x0
0x0000000000000034:  9F 3F 03 D5    dsb sy
0x0000000000000038:  DF 3F 03 D5    isb 
0x000000000000003c:  E0 7F 00 58    ldr x0, #0x1038
0x0000000000000040:  02 00 40 F9    ldr x2, [x0]
0x0000000000000044:  00 00 00 14    b   #0x44
0x0000000000000048:  1F 20 03 D5    nop 
0x000000000000004c:  1F 20 03 D5    nop 
0x0000000000000050:  1F 20 03 D5    nop 
0x0000000000000054:  1F 20 03 D5    nop 
*/
