```mermaid
flowchart TD
START --> arm64_head
arm64_head --> qemu_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L105" "arch/arm64/src/common/arm64_head.S " _blank
qemu_lowputc --> arm64_head
click qemu_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S#L62" "arch/arm64/src/qemu/qemu_lowputc.S " _blank
arm64_head --> qemu_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L228" "arch/arm64/src/common/arm64_head.S " _blank
qemu_lowputc --> arm64_head
click qemu_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S#L91" "arch/arm64/src/qemu/qemu_lowputc.S " _blank
arm64_head --> qemu_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
qemu_lowputc --> arm64_head
click qemu_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S#L91" "arch/arm64/src/qemu/qemu_lowputc.S " _blank
arm64_head --> qemu_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
qemu_lowputc --> arm64_head
click qemu_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S#L91" "arch/arm64/src/qemu/qemu_lowputc.S " _blank
arm64_head --> qemu_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
qemu_lowputc --> arm64_head
click qemu_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S#L91" "arch/arm64/src/qemu/qemu_lowputc.S " _blank
arm64_head --> qemu_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
qemu_lowputc --> arm64_head
click qemu_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S#L91" "arch/arm64/src/qemu/qemu_lowputc.S " _blank
arm64_head --> qemu_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
qemu_lowputc --> arm64_head
click qemu_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S#L91" "arch/arm64/src/qemu/qemu_lowputc.S " _blank
arm64_head --> qemu_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
arm64_head --> arm64_el_init
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
arm64_head --> arm64_boot_el2_init
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
arm64_boot_el2_init --> arm64_boot_el1_init
click arm64_boot_el2_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L160" "arch/arm64/src/common/arm64_boot.c " _blank
arm64_head --> arm64_boot_el1_init
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
arm64_boot_el1_init --> arm64_chip_boot
click arm64_boot_el1_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L204" "arch/arm64/src/common/arm64_boot.c " _blank
arm64_chip_boot --> init_xlat_tables
click arm64_chip_boot href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_boot.c#L158" "arch/arm64/src/qemu/qemu_boot.c " _blank
init_xlat_tables --> arm64_mmu_init
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L477" "arch/arm64/src/common/arm64_mmu.c " _blank
arm64_mmu_init --> enable_mmu_el1
click arm64_mmu_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L661" "arch/arm64/src/common/arm64_mmu.c " _blank
enable_mmu_el1 --> arm64_boot_el1_init
click enable_mmu_el1 href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L607" "arch/arm64/src/common/arm64_mmu.c " _blank
arm64_boot_el1_init --> new_prealloc_table
click arm64_boot_el1_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L214" "arch/arm64/src/common/arm64_boot.c " _blank
new_prealloc_table --> calculate_pte_index
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> init_xlat_tables
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L287" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L487" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> init_xlat_tables
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L333" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> enable_mmu_el1
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L497" "arch/arm64/src/common/arm64_mmu.c " _blank
enable_mmu_el1 --> setup_page_tables
click enable_mmu_el1 href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L616" "arch/arm64/src/common/arm64_mmu.c " _blank
setup_page_tables --> enable_mmu_el1
click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L546" "arch/arm64/src/common/arm64_mmu.c " _blank
enable_mmu_el1 --> arm64_boot_el1_init
click enable_mmu_el1 href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L607" "arch/arm64/src/common/arm64_mmu.c " _blank
arm64_boot_el1_init --> new_prealloc_table
click arm64_boot_el1_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L214" "arch/arm64/src/common/arm64_boot.c " _blank
new_prealloc_table --> calculate_pte_index
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> set_pte_block_desc
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L287" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> init_xlat_tables
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L385" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> calculate_pte_index
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L519" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> init_xlat_tables
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L289" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> calculate_pte_index
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L519" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> init_xlat_tables
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L287" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L487" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> init_xlat_tables
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L333" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L477" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> init_xlat_tables
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L370" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> calculate_pte_index
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L519" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> set_pte_block_desc
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L287" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> new_prealloc_table
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L385" "arch/arm64/src/common/arm64_mmu.c " _blank
new_prealloc_table --> set_pte_table_desc
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> calculate_pte_index
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L519" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> calculate_pte_index
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L519" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L487" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L477" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> calculate_pte_index
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L519" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> set_pte_block_desc
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L287" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> new_prealloc_table
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L385" "arch/arm64/src/common/arm64_mmu.c " _blank
new_prealloc_table --> set_pte_table_desc
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> new_prealloc_table
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L385" "arch/arm64/src/common/arm64_mmu.c " _blank
new_prealloc_table --> set_pte_table_desc
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> new_prealloc_table
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L385" "arch/arm64/src/common/arm64_mmu.c " _blank
new_prealloc_table --> set_pte_table_desc
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> new_prealloc_table
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L385" "arch/arm64/src/common/arm64_mmu.c " _blank
new_prealloc_table --> set_pte_table_desc
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> new_prealloc_table
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L385" "arch/arm64/src/common/arm64_mmu.c " _blank
new_prealloc_table --> set_pte_table_desc
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
new_prealloc_table --> set_pte_table_desc
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
new_prealloc_table --> set_pte_table_desc
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> enable_mmu_el1
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L496" "arch/arm64/src/common/arm64_mmu.c " _blank
enable_mmu_el1 --> setup_page_tables
click enable_mmu_el1 href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L616" "arch/arm64/src/common/arm64_mmu.c " _blank
setup_page_tables --> enable_mmu_el1
click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L546" "arch/arm64/src/common/arm64_mmu.c " _blank
enable_mmu_el1 --> arm64_chip_boot
click enable_mmu_el1 href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L605" "arch/arm64/src/common/arm64_mmu.c " _blank
arm64_chip_boot --> inode_alloc
click arm64_chip_boot href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_boot.c#L166" "arch/arm64/src/qemu/qemu_boot.c " _blank
inode_alloc --> arm64_chip_boot
click inode_alloc href "https://github.com/apache/nuttx/blob/master/fs/inode/fs_inodereserve.c#L101" "fs/inode/fs_inodereserve.c " _blank
arm64_chip_boot --> pl011_irq_tx_ready
click arm64_chip_boot href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_boot.c#L166" "arch/arm64/src/qemu/qemu_boot.c " _blank
pl011_irq_tx_ready --> fdt_register
click pl011_irq_tx_ready href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_pl011.c#L602" "drivers/serial/uart_pl011.c " _blank
fdt_register --> devnull_poll
click fdt_register href "https://github.com/apache/nuttx/blob/master/drivers/devicetree/fdt.c#L68" "drivers/devicetree/fdt.c " _blank
devnull_poll --> devzero_read
click devnull_poll href "https://github.com/apache/nuttx/blob/master/drivers/misc/dev_null.c#L114" "drivers/misc/dev_null.c " _blank
devzero_read --> pl011_txready
click devzero_read href "https://github.com/apache/nuttx/blob/master/drivers/misc/dev_zero.c#L83" "drivers/misc/dev_zero.c " _blank
pl011_txready --> devnull_poll
click pl011_txready href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_pl011.c#L633" "drivers/serial/uart_pl011.c " _blank
devnull_poll --> arm64_boot_el1_init
click devnull_poll href "https://github.com/apache/nuttx/blob/master/drivers/misc/dev_null.c#L114" "drivers/misc/dev_null.c " _blank
arm64_boot_el1_init --> addrenv_take
click arm64_boot_el1_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L206" "arch/arm64/src/common/arm64_boot.c " _blank
addrenv_take --> STUB_utimens
click addrenv_take href "https://github.com/apache/nuttx/blob/master/sched/addrenv/addrenv.c#L395" "sched/addrenv/addrenv.c " _blank
STUB_utimens --> STUB_writev
click STUB_utimens href "https://github.com/apache/nuttx/blob/master/syscall/stubs/STUB_utimens.c#L7" "syscall/stubs/STUB_utimens.c " _blank
STUB_writev --> addrenv_drop
click STUB_writev href "https://github.com/apache/nuttx/blob/master/syscall/stubs/STUB_writev.c#L7" "syscall/stubs/STUB_writev.c " _blank
addrenv_drop --> lib_checkbase
click addrenv_drop href "https://github.com/apache/nuttx/blob/master/sched/addrenv/addrenv.c#L461" "sched/addrenv/addrenv.c " _blank
lib_checkbase --> addrenv_switch
click lib_checkbase href "https://github.com/apache/nuttx/blob/master/libs/libc/stdlib/lib_checkbase.c#L71" "libs/libc/stdlib/lib_checkbase.c " _blank
addrenv_switch --> up_irq_restore
click addrenv_switch href "https://github.com/apache/nuttx/blob/master/sched/addrenv/addrenv.c#L155" "sched/addrenv/addrenv.c " _blank
up_irq_restore --> addrenv_select
click up_irq_restore href "https://github.com/apache/nuttx/blob/master/include/arch/irq.h#L382" "include/arch/irq.h " _blank
addrenv_select --> nxsig_clockwait
click addrenv_select href "https://github.com/apache/nuttx/blob/master/sched/addrenv/addrenv.c#L348" "sched/addrenv/addrenv.c " _blank
nxsig_clockwait --> addrenv_select
click nxsig_clockwait href "https://github.com/apache/nuttx/blob/master/sched/signal/sig_timedwait.c#L307" "sched/signal/sig_timedwait.c " _blank
addrenv_select --> up_schedule_sigaction
click addrenv_select href "https://github.com/apache/nuttx/blob/master/sched/addrenv/addrenv.c#L349" "sched/addrenv/addrenv.c " _blank
up_schedule_sigaction --> arm64_init_signal_process
click up_schedule_sigaction href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_schedulesigaction.c#L143" "arch/arm64/src/common/arm64_schedulesigaction.c " _blank
arm64_init_signal_process --> addrenv_select
click arm64_init_signal_process href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_schedulesigaction.c#L57" "arch/arm64/src/common/arm64_schedulesigaction.c " _blank
addrenv_select --> mm_heapmember
click addrenv_select href "https://github.com/apache/nuttx/blob/master/sched/addrenv/addrenv.c#L351" "sched/addrenv/addrenv.c " _blank
mm_heapmember --> mm_map_add
click mm_heapmember href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_heapmember.c#L85" "mm/mm_heap/mm_heapmember.c " _blank
mm_map_add --> mm_map_find
click mm_map_add href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L235" "mm/map/mm_map.c " _blank
mm_map_find --> STUB_utimens
click mm_map_find href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L284" "mm/map/mm_map.c " _blank
STUB_utimens --> STUB_writev
click STUB_utimens href "https://github.com/apache/nuttx/blob/master/syscall/stubs/STUB_utimens.c#L7" "syscall/stubs/STUB_utimens.c " _blank
STUB_writev --> in_range
click STUB_writev href "https://github.com/apache/nuttx/blob/master/syscall/stubs/STUB_writev.c#L7" "syscall/stubs/STUB_writev.c " _blank
in_range --> mm_map_find
click in_range href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L48" "mm/map/mm_map.c " _blank
mm_map_find --> strncmp
click mm_map_find href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L295" "mm/map/mm_map.c " _blank
strncmp --> lib_get_tempbuffer
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L92" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
lib_get_tempbuffer --> strncmp
click lib_get_tempbuffer href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_tempbuffer.c#L87" "libs/libc/misc/lib_tempbuffer.c " _blank
strncmp --> lib_get_tempbuffer
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L106" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
lib_get_tempbuffer --> strncmp
click lib_get_tempbuffer href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_tempbuffer.c#L101" "libs/libc/misc/lib_tempbuffer.c " _blank
strncmp --> mm_map_find
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L116" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
mm_map_find --> mm_map_initialize
click mm_map_find href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L299" "mm/map/mm_map.c " _blank
mm_map_initialize --> mm_map_remove
click mm_map_initialize href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L134" "mm/map/mm_map.c " _blank
mm_map_remove --> nxtask_argvstr
click mm_map_remove href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L315" "mm/map/mm_map.c " _blank
nxtask_argvstr --> mm_map_remove
click nxtask_argvstr href "https://github.com/apache/nuttx/blob/master/sched/task/task_argvstr.c#L59" "sched/task/task_argvstr.c " _blank
mm_map_remove --> strncmp
click mm_map_remove href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L378" "mm/map/mm_map.c " _blank
strncmp --> nxtask_argvstr
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L214" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
nxtask_argvstr --> strncmp
click nxtask_argvstr href "https://github.com/apache/nuttx/blob/master/sched/task/task_argvstr.c#L59" "sched/task/task_argvstr.c " _blank
strncmp --> nxsched_set_priority
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L148" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
nxsched_set_priority --> nxsched_blocked_setpriority
click nxsched_set_priority href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_setpriority.c#L432" "sched/sched/sched_setpriority.c " _blank
nxsched_blocked_setpriority --> exec_module
click nxsched_blocked_setpriority href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_setpriority.c#L323" "sched/sched/sched_setpriority.c " _blank
exec_module --> nxsched_add_prioritized
click exec_module href "https://github.com/apache/nuttx/blob/master/binfmt/binfmt_execmodule.c#L202" "binfmt/binfmt_execmodule.c " _blank
nxsched_add_prioritized --> strncmp
click nxsched_add_prioritized href "https://github.com/apache/nuttx/blob/master/sched/sched/sched.h#L458" "sched/sched/sched.h " _blank
strncmp --> nxtask_argvstr
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L234" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
nxtask_argvstr --> strncmp
click nxtask_argvstr href "https://github.com/apache/nuttx/blob/master/sched/task/task_argvstr.c#L59" "sched/task/task_argvstr.c " _blank
strncmp --> mm_map_destroy
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L241" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
mm_map_destroy --> mm_map_add
click mm_map_destroy href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L175" "mm/map/mm_map.c " _blank
mm_map_add --> sq_remfirst
click mm_map_add href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L198" "mm/map/mm_map.c " _blank
strncmp --> nxtask_argvstr
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L145" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
arch_strnlen --> nxsched_set_scheduler
click arch_strnlen href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strnlen.S#L81" "libs/libc/machine/arm64/gnu/arch_strnlen.S " _blank
nxsched_set_scheduler --> exec_module
click nxsched_set_scheduler href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_setscheduler.c#L134" "sched/sched/sched_setscheduler.c " _blank
exec_module --> sched_setscheduler
click exec_module href "https://github.com/apache/nuttx/blob/master/binfmt/binfmt_execmodule.c#L232" "binfmt/binfmt_execmodule.c " _blank
sched_setscheduler --> arch_strnlen
click sched_setscheduler href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_setscheduler.c#L319" "sched/sched/sched_setscheduler.c " _blank
arch_strnlen --> strnlen
click arch_strnlen href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strnlen.S#L86" "libs/libc/machine/arm64/gnu/arch_strnlen.S " _blank
strnlen --> mm_map_remove
click strnlen href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strnlen.S#L92" "libs/libc/machine/arm64/gnu/arch_strnlen.S " _blank
mm_map_remove --> meminfo_read
click mm_map_remove href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L359" "mm/map/mm_map.c " _blank
meminfo_read --> mm_map_remove
click meminfo_read href "https://github.com/apache/nuttx/blob/master/fs/procfs/fs_procfsmeminfo.c#L294" "fs/procfs/fs_procfsmeminfo.c " _blank
mm_map_remove --> mm_heapmember
click mm_map_remove href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L320" "mm/map/mm_map.c " _blank
mm_heapmember --> addrenv_select
click mm_heapmember href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_heapmember.c#L93" "mm/mm_heap/mm_heapmember.c " _blank
addrenv_select --> create_region
click addrenv_select href "https://github.com/apache/nuttx/blob/master/sched/addrenv/addrenv.c#L352" "sched/addrenv/addrenv.c " _blank
create_region --> up_addrenv_destroy
click create_region href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L282" "arch/arm64/src/common/arm64_addrenv.c " _blank
up_addrenv_destroy --> addrenv_select
click up_addrenv_destroy href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L552" "arch/arm64/src/common/arm64_addrenv.c " _blank
addrenv_select --> memdump_handler
click addrenv_select href "https://github.com/apache/nuttx/blob/master/sched/addrenv/addrenv.c#L354" "sched/addrenv/addrenv.c " _blank
memdump_handler --> mm_memalign
click memdump_handler href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_memdump.c#L165" "mm/mm_heap/mm_memdump.c " _blank
mm_memalign --> mm_addfreechunk
click mm_memalign href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_memalign.c#L273" "mm/mm_heap/mm_memalign.c " _blank
mm_addfreechunk --> memdump_handler
click mm_addfreechunk href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L337" "mm/mm_heap/mm.h " _blank
memdump_handler --> mm_addfreechunk
click memdump_handler href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_memdump.c#L164" "mm/mm_heap/mm_memdump.c " _blank
mm_addfreechunk --> gettimeofday
click mm_addfreechunk href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L326" "mm/mm_heap/mm.h " _blank
gettimeofday --> syslog
click gettimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_gettimeofday.c#L69" "libs/libc/time/lib_gettimeofday.c " _blank
syslog --> mm_map_remove
click syslog href "https://github.com/apache/nuttx/blob/master/libs/libc/syslog/lib_syslog.c#L101" "libs/libc/syslog/lib_syslog.c " _blank
mm_map_remove --> sq_remafter
click mm_map_remove href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L322" "mm/map/mm_map.c " _blank
sq_remafter --> syslog
click sq_remafter href "https://github.com/apache/nuttx/blob/master/include/nuttx/queue.h#L422" "include/nuttx/queue.h " _blank
syslog --> mm_map_remove
click syslog href "https://github.com/apache/nuttx/blob/master/libs/libc/syslog/lib_syslog.c#L100" "libs/libc/syslog/lib_syslog.c " _blank
mm_map_remove --> syslog
click mm_map_remove href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L353" "mm/map/mm_map.c " _blank
syslog --> gettimeofday
click syslog href "https://github.com/apache/nuttx/blob/master/libs/libc/syslog/lib_syslog.c#L95" "libs/libc/syslog/lib_syslog.c " _blank
gettimeofday --> mm_map_remove
click gettimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_gettimeofday.c#L86" "libs/libc/time/lib_gettimeofday.c " _blank
mm_map_remove --> nxtask_argvstr
click mm_map_remove href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L315" "mm/map/mm_map.c " _blank
nxtask_argvstr --> mm_map_remove
click nxtask_argvstr href "https://github.com/apache/nuttx/blob/master/sched/task/task_argvstr.c#L59" "sched/task/task_argvstr.c " _blank
strncmp --> nxtask_argvstr
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L214" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
strncmp --> nxsched_set_priority
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L148" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
nxsched_set_priority --> nxsched_blocked_setpriority
click nxsched_set_priority href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_setpriority.c#L432" "sched/sched/sched_setpriority.c " _blank
nxsched_blocked_setpriority --> exec_module
click nxsched_blocked_setpriority href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_setpriority.c#L323" "sched/sched/sched_setpriority.c " _blank
exec_module --> nxsched_add_prioritized
click exec_module href "https://github.com/apache/nuttx/blob/master/binfmt/binfmt_execmodule.c#L202" "binfmt/binfmt_execmodule.c " _blank
strncmp --> nxtask_argvstr
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L234" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
strncmp --> gettimeofday
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L241" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
gettimeofday --> settimeofday
click gettimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_gettimeofday.c#L82" "libs/libc/time/lib_gettimeofday.c " _blank
settimeofday --> time
click settimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_settimeofday.c#L65" "libs/libc/time/lib_settimeofday.c " _blank
time --> nanosleep
click time href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_time.c#L63" "libs/libc/time/lib_time.c " _blank
nanosleep --> settimeofday
click nanosleep href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_nanosleep.c#L103" "libs/libc/time/lib_nanosleep.c " _blank
settimeofday --> time
click settimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_settimeofday.c#L74" "libs/libc/time/lib_settimeofday.c " _blank
time --> nanosleep
click time href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_time.c#L63" "libs/libc/time/lib_time.c " _blank
nanosleep --> settimeofday
click nanosleep href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_nanosleep.c#L103" "libs/libc/time/lib_nanosleep.c " _blank
settimeofday --> time
click settimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_settimeofday.c#L74" "libs/libc/time/lib_settimeofday.c " _blank
time --> nanosleep
click time href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_time.c#L63" "libs/libc/time/lib_time.c " _blank
nanosleep --> settimeofday
click nanosleep href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_nanosleep.c#L103" "libs/libc/time/lib_nanosleep.c " _blank
settimeofday --> time
click settimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_settimeofday.c#L74" "libs/libc/time/lib_settimeofday.c " _blank
time --> nanosleep
click time href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_time.c#L63" "libs/libc/time/lib_time.c " _blank
nanosleep --> settimeofday
click nanosleep href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_nanosleep.c#L103" "libs/libc/time/lib_nanosleep.c " _blank
settimeofday --> time
click settimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_settimeofday.c#L74" "libs/libc/time/lib_settimeofday.c " _blank
time --> nanosleep
click time href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_time.c#L63" "libs/libc/time/lib_time.c " _blank
nanosleep --> settimeofday
click nanosleep href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_nanosleep.c#L103" "libs/libc/time/lib_nanosleep.c " _blank
settimeofday --> time
click settimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_settimeofday.c#L74" "libs/libc/time/lib_settimeofday.c " _blank
time --> nanosleep
click time href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_time.c#L63" "libs/libc/time/lib_time.c " _blank
nanosleep --> settimeofday
click nanosleep href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_nanosleep.c#L103" "libs/libc/time/lib_nanosleep.c " _blank
settimeofday --> time
click settimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_settimeofday.c#L74" "libs/libc/time/lib_settimeofday.c " _blank
time --> nanosleep
click time href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_time.c#L63" "libs/libc/time/lib_time.c " _blank
nanosleep --> settimeofday
click nanosleep href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_nanosleep.c#L103" "libs/libc/time/lib_nanosleep.c " _blank
settimeofday --> time
click settimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_settimeofday.c#L74" "libs/libc/time/lib_settimeofday.c " _blank
time --> nanosleep
click time href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_time.c#L63" "libs/libc/time/lib_time.c " _blank
nanosleep --> tls_get_info
click nanosleep href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_nanosleep.c#L95" "libs/libc/time/lib_nanosleep.c " _blank
tls_get_info --> up_irq_save
click tls_get_info href "https://github.com/apache/nuttx/blob/master/libs/libc/tls/tls_getinfo.c#L63" "libs/libc/tls/tls_getinfo.c " _blank
up_irq_save --> sethostname
click up_irq_save href "https://github.com/apache/nuttx/blob/master/include/arch/irq.h#L349" "include/arch/irq.h " _blank
sethostname --> memchr
click sethostname href "https://github.com/apache/nuttx/blob/master/libs/libc/unistd/lib_sethostname.c#L108" "libs/libc/unistd/lib_sethostname.c " _blank
memchr --> strrchr
click memchr href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_memchr.S#L110" "libs/libc/machine/arm64/gnu/arch_memchr.S " _blank
strrchr --> memchr
click strrchr href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strrchr.S#L164" "libs/libc/machine/arm64/gnu/arch_strrchr.S " _blank
settimeofday --> sq_remfirst
click settimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_settimeofday.c#L75" "libs/libc/time/lib_settimeofday.c " _blank
strncmp --> nxtask_argvstr
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L145" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L148" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
arch_strnlen --> nxsched_set_scheduler
click arch_strnlen href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strnlen.S#L81" "libs/libc/machine/arm64/gnu/arch_strnlen.S " _blank
nxsched_set_scheduler --> exec_module
click nxsched_set_scheduler href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_setscheduler.c#L134" "sched/sched/sched_setscheduler.c " _blank
exec_module --> sched_setscheduler
click exec_module href "https://github.com/apache/nuttx/blob/master/binfmt/binfmt_execmodule.c#L232" "binfmt/binfmt_execmodule.c " _blank
sched_setscheduler --> arch_strnlen
click sched_setscheduler href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_setscheduler.c#L319" "sched/sched/sched_setscheduler.c " _blank
arch_strnlen --> strnlen
click arch_strnlen href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strnlen.S#L86" "libs/libc/machine/arm64/gnu/arch_strnlen.S " _blank
settimeofday --> memchr
click settimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_settimeofday.c#L79" "libs/libc/time/lib_settimeofday.c " _blank
memchr --> mm_addfreechunk
click memchr href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_memchr.S#L155" "libs/libc/machine/arm64/gnu/arch_memchr.S " _blank
mm_addfreechunk --> mm_size2ndx
click mm_addfreechunk href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L326" "mm/mm_heap/mm.h " _blank
mm_size2ndx --> STUB_utimens
click mm_size2ndx href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L314" "mm/mm_heap/mm.h " _blank
STUB_utimens --> STUB_writev
click STUB_utimens href "https://github.com/apache/nuttx/blob/master/syscall/stubs/STUB_utimens.c#L7" "syscall/stubs/STUB_utimens.c " _blank
click STUB_writev href "https://github.com/apache/nuttx/blob/master/syscall/stubs/STUB_writev.c#L7" "syscall/stubs/STUB_writev.c " _blank
mm_size2ndx --> mm_realloc
click mm_size2ndx href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L314" "mm/mm_heap/mm.h " _blank
strncmp --> lib_get_tempbuffer
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L92" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
strncmp --> lib_get_tempbuffer
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L106" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
strncmp --> mm_realloc
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L116" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
mm_realloc --> memdump_handler
click mm_realloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_realloc.c#L117" "mm/mm_heap/mm_realloc.c " _blank
memdump_handler --> addrenv_select
click memdump_handler href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_memdump.c#L168" "mm/mm_heap/mm_memdump.c " _blank
addrenv_select --> kmm_initialize
click addrenv_select href "https://github.com/apache/nuttx/blob/master/sched/addrenv/addrenv.c#L354" "sched/addrenv/addrenv.c " _blank
kmm_initialize --> up_addrenv_create
click kmm_initialize href "https://github.com/apache/nuttx/blob/master/mm/kmm_heap/kmm_initialize.c#L61" "mm/kmm_heap/kmm_initialize.c " _blank
up_addrenv_create --> mmu_get_region_size
click up_addrenv_create href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L487" "arch/arm64/src/common/arm64_addrenv.c " _blank
mmu_get_region_size --> up_addrenv_create
click mmu_get_region_size href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L784" "arch/arm64/src/common/arm64_mmu.c " _blank
up_addrenv_create --> copy_kernel_mappings
click up_addrenv_create href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L515" "arch/arm64/src/common/arm64_addrenv.c " _blank
copy_kernel_mappings --> up_addrenv_create
click copy_kernel_mappings href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L218" "arch/arm64/src/common/arm64_addrenv.c " _blank
up_addrenv_create --> mmu_ln_setentry
click up_addrenv_create href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L433" "arch/arm64/src/common/arm64_addrenv.c " _blank
mmu_ln_setentry --> arm64_fpu_func
click mmu_ln_setentry href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L725" "arch/arm64/src/common/arm64_mmu.c " _blank
arm64_fpu_func --> arm64_vectors
click arm64_fpu_func href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_fpu_func.S#L67" "arch/arm64/src/common/arm64_fpu_func.S " _blank
arm64_vectors --> arm64_smccc
click arm64_vectors href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_vectors.S#L270" "arch/arm64/src/common/arm64_vectors.S " _blank
arm64_smccc --> mmu_ln_getentry
click arm64_smccc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_smccc.S#L57" "arch/arm64/src/common/arm64_smccc.S " _blank
mmu_ln_getentry --> up_addrenv_vtext
click mmu_ln_getentry href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L747" "arch/arm64/src/common/arm64_mmu.c " _blank
up_addrenv_vtext --> up_addrenv_create
click up_addrenv_vtext href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L628" "arch/arm64/src/common/arm64_addrenv.c " _blank
up_addrenv_create --> copy_kernel_mappings
click up_addrenv_create href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L517" "arch/arm64/src/common/arm64_addrenv.c " _blank
copy_kernel_mappings --> up_addrenv_create
click copy_kernel_mappings href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L218" "arch/arm64/src/common/arm64_addrenv.c " _blank
up_addrenv_create --> mmu_ln_setentry
click up_addrenv_create href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L433" "arch/arm64/src/common/arm64_addrenv.c " _blank
mmu_ln_setentry --> arm64_fpu_func
click mmu_ln_setentry href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L725" "arch/arm64/src/common/arm64_mmu.c " _blank
arm64_fpu_func --> arm64_vectors
click arm64_fpu_func href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_fpu_func.S#L67" "arch/arm64/src/common/arm64_fpu_func.S " _blank
arm64_vectors --> arm64_smccc
click arm64_vectors href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_vectors.S#L270" "arch/arm64/src/common/arm64_vectors.S " _blank
arm64_smccc --> arm64_fpu_func
click arm64_smccc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_smccc.S#L70" "arch/arm64/src/common/arm64_smccc.S " _blank
arm64_fpu_func --> arm64_smccc
click arm64_fpu_func href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_fpu_func.S#L53" "arch/arm64/src/common/arm64_fpu_func.S " _blank
arm64_smccc --> mmu_ln_getentry
click arm64_smccc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_smccc.S#L70" "arch/arm64/src/common/arm64_smccc.S " _blank
mmu_ln_getentry --> up_addrenv_vtext
click mmu_ln_getentry href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L747" "arch/arm64/src/common/arm64_mmu.c " _blank
up_addrenv_vtext --> up_addrenv_create
click up_addrenv_vtext href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L628" "arch/arm64/src/common/arm64_addrenv.c " _blank
up_addrenv_create --> kmm_initialize
click up_addrenv_create href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv.c#L517" "arch/arm64/src/common/arm64_addrenv.c " _blank
kmm_initialize --> mm_memalign
click kmm_initialize href "https://github.com/apache/nuttx/blob/master/mm/kmm_heap/kmm_initialize.c#L62" "mm/kmm_heap/kmm_initialize.c " _blank
mm_memalign --> mm_addfreechunk
click mm_memalign href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_memalign.c#L273" "mm/mm_heap/mm_memalign.c " _blank
mm_addfreechunk --> memdump_handler
click mm_addfreechunk href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L337" "mm/mm_heap/mm.h " _blank
memdump_handler --> mm_addfreechunk
click memdump_handler href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_memdump.c#L164" "mm/mm_heap/mm_memdump.c " _blank
mm_addfreechunk --> gettimeofday
click mm_addfreechunk href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L326" "mm/mm_heap/mm.h " _blank
gettimeofday --> syslog
click gettimeofday href "https://github.com/apache/nuttx/blob/master/libs/libc/time/lib_gettimeofday.c#L69" "libs/libc/time/lib_gettimeofday.c " _blank
mm_map_remove --> sq_remafter
click mm_map_remove href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L322" "mm/map/mm_map.c " _blank
sq_remafter --> syslog
click sq_remafter href "https://github.com/apache/nuttx/blob/master/include/nuttx/queue.h#L422" "include/nuttx/queue.h " _blank
mm_map_remove --> syslog
click mm_map_remove href "https://github.com/apache/nuttx/blob/master/mm/map/mm_map.c#L353" "mm/map/mm_map.c " _blank
syslog --> gettimeofday
click syslog href "https://github.com/apache/nuttx/blob/master/libs/libc/syslog/lib_syslog.c#L95" "libs/libc/syslog/lib_syslog.c " _blank
strncmp --> nxsched_set_priority
click strncmp href "https://github.com/apache/nuttx/blob/master/libs/libc/machine/arm64/gnu/arch_strncmp.S#L148" "libs/libc/machine/arm64/gnu/arch_strncmp.S " _blank
nxsched_set_priority --> nxsched_blocked_setpriority
click nxsched_set_priority href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_setpriority.c#L432" "sched/sched/sched_setpriority.c " _blank
nxsched_blocked_setpriority --> exec_module
click nxsched_blocked_setpriority href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_setpriority.c#L323" "sched/sched/sched_setpriority.c " _blank
exec_module --> nxsched_add_prioritized
```

[Download PDF](nuttx-boot-flow.pdf) / [PNG](nuttx-boot-flow.png) / [SVG](nuttx-boot-flow.svg)

# Unicorn Emulator for Apache NuttX RTOS on QEMU Arm64

Read the articles...

-   ["Inside Arm64 MMU: Unicorn Emulator vs Apache NuttX RTOS"](https://lupyuen.org/articles/unicorn3.html)

-   ["(Possibly) Emulate PinePhone with Unicorn Emulator"](https://lupyuen.github.io/articles/unicorn)

-   ["(Clickable) Call Graph for Apache NuttX Real-Time Operating System"](https://lupyuen.github.io/articles/unicorn2)
