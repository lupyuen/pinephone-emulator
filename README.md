```mermaid
flowchart TD
START --> arm64_head
arm64_head --> a527_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L105" "arch/arm64/src/common/arm64_head.S " _blank
a527_lowputc --> arm64_head
click a527_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_lowputc.S#L47" "arch/arm64/src/a527/a527_lowputc.S " _blank
arm64_head --> a527_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L228" "arch/arm64/src/common/arm64_head.S " _blank
a527_lowputc --> arm64_head
click a527_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_lowputc.S#L76" "arch/arm64/src/a527/a527_lowputc.S " _blank
arm64_head --> a527_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
a527_lowputc --> arm64_head
click a527_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_lowputc.S#L76" "arch/arm64/src/a527/a527_lowputc.S " _blank
arm64_head --> a527_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
a527_lowputc --> arm64_head
click a527_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_lowputc.S#L76" "arch/arm64/src/a527/a527_lowputc.S " _blank
arm64_head --> a527_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
a527_lowputc --> arm64_head
click a527_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_lowputc.S#L76" "arch/arm64/src/a527/a527_lowputc.S " _blank
arm64_head --> a527_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
a527_lowputc --> arm64_head
click a527_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_lowputc.S#L76" "arch/arm64/src/a527/a527_lowputc.S " _blank
arm64_head --> a527_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
a527_lowputc --> arm64_head
click a527_lowputc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_lowputc.S#L76" "arch/arm64/src/a527/a527_lowputc.S " _blank
arm64_head --> a527_lowputc
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
arm64_head --> arm64_el_init
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
arm64_head --> arm64_boot_el1_init
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
arm64_head --> arm64_boot_primary_c_routine
click arm64_head href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L374" "arch/arm64/src/common/arm64_head.S " _blank
arm64_boot_primary_c_routine --> arm64_chip_boot
click arm64_boot_primary_c_routine href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L217" "arch/arm64/src/common/arm64_boot.c " _blank
arm64_chip_boot --> arm64_mmu_init
click arm64_chip_boot href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_boot.c#L231" "arch/arm64/src/a527/a527_boot.c " _blank
arm64_mmu_init --> setup_page_tables
click arm64_mmu_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L661" "arch/arm64/src/common/arm64_mmu.c " _blank
setup_page_tables --> init_xlat_tables
click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L530" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L462" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> init_xlat_tables
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L333" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> setup_page_tables
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L477" "arch/arm64/src/common/arm64_mmu.c " _blank
setup_page_tables --> init_xlat_tables
click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L544" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> pte_desc_type
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L462" "arch/arm64/src/common/arm64_mmu.c " _blank
pte_desc_type --> new_prealloc_table
click pte_desc_type href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L274" "arch/arm64/src/common/arm64_mmu.c " _blank
new_prealloc_table --> calculate_pte_index
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> pte_desc_type
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L286" "arch/arm64/src/common/arm64_mmu.c " _blank
pte_desc_type --> calculate_pte_index
click pte_desc_type href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L274" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> init_xlat_tables
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L287" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L487" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> init_xlat_tables
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L333" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> pte_desc_type
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L457" "arch/arm64/src/common/arm64_mmu.c " _blank
pte_desc_type --> init_xlat_tables
click pte_desc_type href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L274" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> calculate_pte_index
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L512" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> pte_desc_type
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L286" "arch/arm64/src/common/arm64_mmu.c " _blank
pte_desc_type --> calculate_pte_index
click pte_desc_type href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L274" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> init_xlat_tables
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L287" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L487" "arch/arm64/src/common/arm64_mmu.c " _blank
set_pte_block_desc --> init_xlat_tables
click set_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L333" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> pte_desc_type
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L457" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> calculate_pte_index
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L512" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> pte_desc_type
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L286" "arch/arm64/src/common/arm64_mmu.c " _blank
pte_desc_type --> calculate_pte_index
click pte_desc_type href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L274" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L487" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> pte_desc_type
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L457" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> calculate_pte_index
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L512" "arch/arm64/src/common/arm64_mmu.c " _blank
calculate_pte_index --> pte_desc_type
click calculate_pte_index href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L286" "arch/arm64/src/common/arm64_mmu.c " _blank
pte_desc_type --> calculate_pte_index
click pte_desc_type href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L274" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L487" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L487" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L487" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> set_pte_block_desc
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L487" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> setup_page_tables
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L477" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> new_prealloc_table
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L512" "arch/arm64/src/common/arm64_mmu.c " _blank
new_prealloc_table --> split_pte_block_desc
click new_prealloc_table href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L418" "arch/arm64/src/common/arm64_mmu.c " _blank
split_pte_block_desc --> set_pte_table_desc
click split_pte_block_desc href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L445" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> setup_page_tables
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L477" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> setup_page_tables
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L477" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> setup_page_tables
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L477" "arch/arm64/src/common/arm64_mmu.c " _blank
init_xlat_tables --> setup_page_tables
click init_xlat_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L477" "arch/arm64/src/common/arm64_mmu.c " _blank
setup_page_tables --> enable_mmu_el1
click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L555" "arch/arm64/src/common/arm64_mmu.c " _blank
enable_mmu_el1 --> arm64_mmu_init
click enable_mmu_el1 href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L605" "arch/arm64/src/common/arm64_mmu.c " _blank
arm64_mmu_init --> arm64_chip_boot
click arm64_mmu_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L712" "arch/arm64/src/common/arm64_mmu.c " _blank
arm64_chip_boot --> a527_boardinit
click arm64_chip_boot href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_boot.c#L254" "arch/arm64/src/a527/a527_boot.c " _blank
a527_boardinit --> arm64_chip_boot
click a527_boardinit href "https://github.com/apache/nuttx/blob/master/boards/arm64/a527/avaota-a1/src/a527_boardinit.c#L86" "boards/arm64/a527/avaota-a1/src/a527_boardinit.c " _blank
arm64_chip_boot --> arm64_earlyserialinit
click arm64_chip_boot href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_boot.c#L267" "arch/arm64/src/a527/a527_boot.c " _blank
arm64_earlyserialinit --> u16550_earlyserialinit
click arm64_earlyserialinit href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/a527/a527_serial.c#L58" "arch/arm64/src/a527/a527_serial.c " _blank
u16550_earlyserialinit --> u16550_setup
click u16550_earlyserialinit href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L1661" "drivers/serial/uart_16550.c " _blank
u16550_setup --> u16550_serialout
click u16550_setup href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L789" "drivers/serial/uart_16550.c " _blank
u16550_serialout --> u16550_mmio_putreg
click u16550_serialout href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L663" "drivers/serial/uart_16550.c " _blank
u16550_mmio_putreg --> u16550_setup
click u16550_mmio_putreg href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L635" "drivers/serial/uart_16550.c " _blank
u16550_setup --> u16550_serialin
click u16550_setup href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L813" "drivers/serial/uart_16550.c " _blank
u16550_serialin --> u16550_mmio_getreg
click u16550_serialin href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L650" "drivers/serial/uart_16550.c " _blank
u16550_mmio_getreg --> u16550_setup
click u16550_mmio_getreg href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L623" "drivers/serial/uart_16550.c " _blank
u16550_setup --> u16550_wait
click u16550_setup href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L813" "drivers/serial/uart_16550.c " _blank
u16550_wait --> u16550_serialin
click u16550_wait href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L683" "drivers/serial/uart_16550.c " _blank
u16550_serialin --> u16550_mmio_getreg
click u16550_serialin href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L650" "drivers/serial/uart_16550.c " _blank
u16550_mmio_getreg --> u16550_wait
click u16550_mmio_getreg href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L623" "drivers/serial/uart_16550.c " _blank
u16550_wait --> u16550_setup
click u16550_wait href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L690" "drivers/serial/uart_16550.c " _blank
u16550_setup --> u16550_serialout
click u16550_setup href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L855" "drivers/serial/uart_16550.c " _blank
u16550_serialout --> u16550_mmio_putreg
click u16550_serialout href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L663" "drivers/serial/uart_16550.c " _blank
u16550_mmio_putreg --> u16550_divisor
click u16550_mmio_putreg href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L635" "drivers/serial/uart_16550.c " _blank
u16550_divisor --> u16550_serialout
click u16550_divisor href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L765" "drivers/serial/uart_16550.c " _blank
u16550_serialout --> u16550_mmio_putreg
click u16550_serialout href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L663" "drivers/serial/uart_16550.c " _blank
u16550_mmio_putreg --> u16550_setup
click u16550_mmio_putreg href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L635" "drivers/serial/uart_16550.c " _blank
u16550_setup --> u16550_serialout
click u16550_setup href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L873" "drivers/serial/uart_16550.c " _blank
u16550_serialout --> u16550_mmio_putreg
click u16550_serialout href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L663" "drivers/serial/uart_16550.c " _blank
u16550_mmio_putreg --> u16550_setup
click u16550_mmio_putreg href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L635" "drivers/serial/uart_16550.c " _blank
u16550_setup --> u16550_wait
click u16550_setup href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L878" "drivers/serial/uart_16550.c " _blank
u16550_wait --> u16550_serialin
click u16550_wait href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L683" "drivers/serial/uart_16550.c " _blank
u16550_serialin --> u16550_mmio_getreg
click u16550_serialin href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L650" "drivers/serial/uart_16550.c " _blank
u16550_mmio_getreg --> u16550_wait
click u16550_mmio_getreg href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L623" "drivers/serial/uart_16550.c " _blank
u16550_wait --> u16550_setup
click u16550_wait href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L690" "drivers/serial/uart_16550.c " _blank
u16550_setup --> u16550_serialout
click u16550_setup href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L878" "drivers/serial/uart_16550.c " _blank
u16550_serialout --> u16550_mmio_putreg
click u16550_serialout href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L663" "drivers/serial/uart_16550.c " _blank
u16550_mmio_putreg --> u16550_setup
click u16550_mmio_putreg href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L635" "drivers/serial/uart_16550.c " _blank
u16550_setup --> u16550_serialout
click u16550_setup href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L893" "drivers/serial/uart_16550.c " _blank
u16550_serialout --> u16550_mmio_putreg
click u16550_serialout href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L663" "drivers/serial/uart_16550.c " _blank
u16550_setup --> arm64_boot_primary_c_routine
click u16550_setup href "https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L928" "drivers/serial/uart_16550.c " _blank
arm64_boot_primary_c_routine --> nx_start
click arm64_boot_primary_c_routine href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L220" "arch/arm64/src/common/arm64_boot.c " _blank
nx_start --> idle_task_initialize
click nx_start href "https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L524" "sched/init/nx_start.c " _blank
idle_task_initialize --> nx_start
click idle_task_initialize href "https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L362" "sched/init/nx_start.c " _blank
nx_start --> drivers_early_initialize
click nx_start href "https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L543" "sched/init/nx_start.c " _blank
drivers_early_initialize --> nx_start
click drivers_early_initialize href "https://github.com/apache/nuttx/blob/master/drivers/drivers_initialize.c#L95" "drivers/drivers_initialize.c " _blank
nx_start --> up_allocate_kheap
click nx_start href "https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L581" "sched/init/nx_start.c " _blank
up_allocate_kheap --> nx_start
click up_allocate_kheap href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_allocateheap.c#L129" "arch/arm64/src/common/arm64_allocateheap.c " _blank
nx_start --> kmm_initialize
click nx_start href "https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L582" "sched/init/nx_start.c " _blank
kmm_initialize --> mm_initialize
click kmm_initialize href "https://github.com/apache/nuttx/blob/master/mm/kmm_heap/kmm_initialize.c#L61" "mm/kmm_heap/kmm_initialize.c " _blank
mm_initialize --> nxmutex_init
click mm_initialize href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_initialize.c#L234" "mm/mm_heap/mm_initialize.c " _blank
nxmutex_init --> nxsem_init
click nxmutex_init href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L114" "libs/libc/misc/lib_mutex.c " _blank
nxsem_init --> nxmutex_init
click nxsem_init href "https://github.com/apache/nuttx/blob/master/libs/libc/semaphore/sem_init.c#L68" "libs/libc/semaphore/sem_init.c " _blank
nxmutex_init --> nxsem_set_protocol
click nxmutex_init href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L115" "libs/libc/misc/lib_mutex.c " _blank
nxsem_set_protocol --> nxmutex_init
click nxsem_set_protocol href "https://github.com/apache/nuttx/blob/master/libs/libc/semaphore/sem_setprotocol.c#L79" "libs/libc/semaphore/sem_setprotocol.c " _blank
nxmutex_init --> mm_initialize
click nxmutex_init href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L129" "libs/libc/misc/lib_mutex.c " _blank
mm_initialize --> mm_addregion
click mm_initialize href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_initialize.c#L286" "mm/mm_heap/mm_initialize.c " _blank
mm_addregion --> mm_lock
click mm_addregion href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_initialize.c#L104" "mm/mm_heap/mm_initialize.c " _blank
mm_lock --> nxsched_gettid
click mm_lock href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L60" "mm/mm_heap/mm_lock.c " _blank
nxsched_gettid --> mm_lock
click nxsched_gettid href "https://github.com/apache/nuttx/blob/master/sched/task/task_gettid.c#L68" "sched/task/task_gettid.c " _blank
mm_lock --> nxmutex_lock
click mm_lock href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L90" "mm/mm_heap/mm_lock.c " _blank
nxmutex_lock --> nxmutex_is_hold
click nxmutex_lock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L248" "libs/libc/misc/lib_mutex.c " _blank
nxmutex_is_hold --> nxsched_gettid
click nxmutex_is_hold href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L178" "libs/libc/misc/lib_mutex.c " _blank
nxsched_gettid --> nxmutex_is_hold
click nxsched_gettid href "https://github.com/apache/nuttx/blob/master/sched/task/task_gettid.c#L68" "sched/task/task_gettid.c " _blank
nxmutex_is_hold --> nxmutex_lock
click nxmutex_is_hold href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L179" "libs/libc/misc/lib_mutex.c " _blank
nxmutex_lock --> nxsem_wait
click nxmutex_lock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L251" "libs/libc/misc/lib_mutex.c " _blank
nxsem_wait --> nxmutex_lock
click nxsem_wait href "https://github.com/apache/nuttx/blob/master/sched/semaphore/sem_wait.c#L257" "sched/semaphore/sem_wait.c " _blank
nxmutex_lock --> nxsched_gettid
click nxmutex_lock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L256" "libs/libc/misc/lib_mutex.c " _blank
nxsched_gettid --> nxmutex_lock
click nxsched_gettid href "https://github.com/apache/nuttx/blob/master/sched/task/task_gettid.c#L68" "sched/task/task_gettid.c " _blank
nxmutex_lock --> mm_addregion
click nxmutex_lock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L259" "libs/libc/misc/lib_mutex.c " _blank
mm_addregion --> mm_addfreechunk
click mm_addregion href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_initialize.c#L125" "mm/mm_heap/mm_initialize.c " _blank
mm_addfreechunk --> mm_size2ndx
click mm_addfreechunk href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L326" "mm/mm_heap/mm.h " _blank
mm_size2ndx --> mm_addfreechunk
click mm_size2ndx href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L314" "mm/mm_heap/mm.h " _blank
mm_addfreechunk --> mm_addregion
click mm_addfreechunk href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L335" "mm/mm_heap/mm.h " _blank
mm_addregion --> mm_unlock
click mm_addregion href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_initialize.c#L207" "mm/mm_heap/mm_initialize.c " _blank
mm_unlock --> nxmutex_unlock
click mm_unlock href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L111" "mm/mm_heap/mm_lock.c " _blank
nxmutex_unlock --> nxmutex_is_hold
click nxmutex_unlock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L423" "libs/libc/misc/lib_mutex.c " _blank
nxmutex_is_hold --> nxsched_gettid
click nxmutex_is_hold href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L178" "libs/libc/misc/lib_mutex.c " _blank
nxsched_gettid --> nxmutex_is_hold
click nxsched_gettid href "https://github.com/apache/nuttx/blob/master/sched/task/task_gettid.c#L68" "sched/task/task_gettid.c " _blank
nxmutex_is_hold --> nxmutex_unlock
click nxmutex_is_hold href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L179" "libs/libc/misc/lib_mutex.c " _blank
nxmutex_unlock --> nxsem_post
click nxmutex_unlock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L431" "libs/libc/misc/lib_mutex.c " _blank
nxsem_post --> nxmutex_unlock
click nxsem_post href "https://github.com/apache/nuttx/blob/master/sched/semaphore/sem_post.c#L254" "sched/semaphore/sem_post.c " _blank
nxmutex_unlock --> mm_unlock
click nxmutex_unlock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L435" "libs/libc/misc/lib_mutex.c " _blank
mm_unlock --> mm_initialize
click mm_unlock href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L117" "mm/mm_heap/mm_lock.c " _blank
mm_initialize --> procfs_register_meminfo
click mm_initialize href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_initialize.c#L290" "mm/mm_heap/mm_initialize.c " _blank
procfs_register_meminfo --> mm_initialize
click procfs_register_meminfo href "https://github.com/apache/nuttx/blob/master/fs/procfs/fs_procfsmeminfo.c#L720" "fs/procfs/fs_procfsmeminfo.c " _blank
mm_initialize --> kmm_initialize
click mm_initialize href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_initialize.c#L295" "mm/mm_heap/mm_initialize.c " _blank
kmm_initialize --> nx_start
click kmm_initialize href "https://github.com/apache/nuttx/blob/master/mm/kmm_heap/kmm_initialize.c#L62" "mm/kmm_heap/kmm_initialize.c " _blank
nx_start --> up_allocate_pgheap
click nx_start href "https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L591" "sched/init/nx_start.c " _blank
up_allocate_pgheap --> nx_start
click up_allocate_pgheap href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_pgalloc.c#L172" "arch/arm64/src/common/arm64_pgalloc.c " _blank
nx_start --> mm_pginitialize
click nx_start href "https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L592" "sched/init/nx_start.c " _blank
mm_pginitialize --> gran_initialize
click mm_pginitialize href "https://github.com/apache/nuttx/blob/master/mm/mm_gran/mm_pgalloc.c#L99" "mm/mm_gran/mm_pgalloc.c " _blank
gran_initialize --> kmm_zalloc
click gran_initialize href "https://github.com/apache/nuttx/blob/master/mm/mm_gran/mm_graninit.c#L97" "mm/mm_gran/mm_graninit.c " _blank
kmm_zalloc --> mm_zalloc
click kmm_zalloc href "https://github.com/apache/nuttx/blob/master/mm/kmm_heap/kmm_zalloc.c#L52" "mm/kmm_heap/kmm_zalloc.c " _blank
mm_zalloc --> mm_malloc
click mm_zalloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_zalloc.c#L45" "mm/mm_heap/mm_zalloc.c " _blank
mm_malloc --> free_delaylist
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L170" "mm/mm_heap/mm_malloc.c " _blank
free_delaylist --> up_irq_save
click free_delaylist href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L58" "mm/mm_heap/mm_malloc.c " _blank
up_irq_save --> mm_lock_irq
click up_irq_save href "https://github.com/apache/nuttx/blob/master/arch/arm64/include/irq.h#L349" "arch/arm64/include/irq.h " _blank
mm_lock_irq --> free_delaylist
click mm_lock_irq href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L132" "mm/mm_heap/mm_lock.c " _blank
free_delaylist --> up_irq_restore
click free_delaylist href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L85" "mm/mm_heap/mm_malloc.c " _blank
up_irq_restore --> mm_unlock_irq
click up_irq_restore href "https://github.com/apache/nuttx/blob/master/arch/arm64/include/irq.h#L382" "arch/arm64/include/irq.h " _blank
mm_unlock_irq --> free_delaylist
click mm_unlock_irq href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L146" "mm/mm_heap/mm_lock.c " _blank
free_delaylist --> mm_malloc
click free_delaylist href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L91" "mm/mm_heap/mm_malloc.c " _blank
mm_malloc --> mm_lock
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L197" "mm/mm_heap/mm_malloc.c " _blank
mm_lock --> nxsched_gettid
click mm_lock href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L60" "mm/mm_heap/mm_lock.c " _blank
nxsched_gettid --> mm_lock
click nxsched_gettid href "https://github.com/apache/nuttx/blob/master/sched/task/task_gettid.c#L68" "sched/task/task_gettid.c " _blank
mm_lock --> nxmutex_lock
click mm_lock href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L90" "mm/mm_heap/mm_lock.c " _blank
nxmutex_lock --> nxmutex_is_hold
click nxmutex_lock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L248" "libs/libc/misc/lib_mutex.c " _blank
nxmutex_is_hold --> nxsched_gettid
click nxmutex_is_hold href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L178" "libs/libc/misc/lib_mutex.c " _blank
nxsched_gettid --> nxmutex_is_hold
click nxsched_gettid href "https://github.com/apache/nuttx/blob/master/sched/task/task_gettid.c#L68" "sched/task/task_gettid.c " _blank
nxmutex_is_hold --> nxmutex_lock
click nxmutex_is_hold href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L179" "libs/libc/misc/lib_mutex.c " _blank
nxmutex_lock --> nxsem_wait
click nxmutex_lock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L251" "libs/libc/misc/lib_mutex.c " _blank
nxsem_wait --> nxmutex_lock
click nxsem_wait href "https://github.com/apache/nuttx/blob/master/sched/semaphore/sem_wait.c#L257" "sched/semaphore/sem_wait.c " _blank
nxmutex_lock --> nxsched_gettid
click nxmutex_lock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L256" "libs/libc/misc/lib_mutex.c " _blank
nxsched_gettid --> nxmutex_lock
click nxsched_gettid href "https://github.com/apache/nuttx/blob/master/sched/task/task_gettid.c#L68" "sched/task/task_gettid.c " _blank
nxmutex_lock --> mm_malloc
click nxmutex_lock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L259" "libs/libc/misc/lib_mutex.c " _blank
mm_malloc --> mm_size2ndx
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L214" "mm/mm_heap/mm_malloc.c " _blank
mm_size2ndx --> mm_malloc
click mm_size2ndx href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L314" "mm/mm_heap/mm.h " _blank
mm_malloc --> mm_addfreechunk
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L227" "mm/mm_heap/mm_malloc.c " _blank
mm_addfreechunk --> mm_size2ndx
click mm_addfreechunk href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L326" "mm/mm_heap/mm.h " _blank
mm_size2ndx --> mm_addfreechunk
click mm_size2ndx href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L314" "mm/mm_heap/mm.h " _blank
mm_addfreechunk --> mm_malloc
click mm_addfreechunk href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm.h#L341" "mm/mm_heap/mm.h " _blank
mm_malloc --> mm_heapmember
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L311" "mm/mm_heap/mm_malloc.c " _blank
mm_heapmember --> mm_malloc
click mm_heapmember href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_heapmember.c#L85" "mm/mm_heap/mm_heapmember.c " _blank
mm_malloc --> mm_unlock
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L322" "mm/mm_heap/mm_malloc.c " _blank
mm_unlock --> nxmutex_unlock
click mm_unlock href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L111" "mm/mm_heap/mm_lock.c " _blank
nxmutex_unlock --> nxmutex_is_hold
click nxmutex_unlock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L423" "libs/libc/misc/lib_mutex.c " _blank
nxmutex_is_hold --> nxsched_gettid
click nxmutex_is_hold href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L178" "libs/libc/misc/lib_mutex.c " _blank
nxsched_gettid --> nxmutex_is_hold
click nxsched_gettid href "https://github.com/apache/nuttx/blob/master/sched/task/task_gettid.c#L68" "sched/task/task_gettid.c " _blank
nxmutex_is_hold --> nxmutex_unlock
click nxmutex_is_hold href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L179" "libs/libc/misc/lib_mutex.c " _blank
nxmutex_unlock --> nxsem_post
click nxmutex_unlock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L431" "libs/libc/misc/lib_mutex.c " _blank
nxsem_post --> nxmutex_unlock
click nxsem_post href "https://github.com/apache/nuttx/blob/master/sched/semaphore/sem_post.c#L254" "sched/semaphore/sem_post.c " _blank
nxmutex_unlock --> mm_unlock
click nxmutex_unlock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L435" "libs/libc/misc/lib_mutex.c " _blank
mm_unlock --> mm_malloc
click mm_unlock href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L117" "mm/mm_heap/mm_lock.c " _blank
mm_malloc --> mm_zalloc
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L410" "mm/mm_heap/mm_malloc.c " _blank
mm_zalloc --> gran_initialize
click mm_zalloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_zalloc.c#L46" "mm/mm_heap/mm_zalloc.c " _blank
gran_initialize --> nxmutex_init
click gran_initialize href "https://github.com/apache/nuttx/blob/master/mm/mm_gran/mm_graninit.c#L130" "mm/mm_gran/mm_graninit.c " _blank
nxmutex_init --> nxsem_init
click nxmutex_init href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L114" "libs/libc/misc/lib_mutex.c " _blank
nxsem_init --> nxmutex_init
click nxsem_init href "https://github.com/apache/nuttx/blob/master/libs/libc/semaphore/sem_init.c#L68" "libs/libc/semaphore/sem_init.c " _blank
nxmutex_init --> nxsem_set_protocol
click nxmutex_init href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L115" "libs/libc/misc/lib_mutex.c " _blank
nxsem_set_protocol --> nxmutex_init
click nxsem_set_protocol href "https://github.com/apache/nuttx/blob/master/libs/libc/semaphore/sem_setprotocol.c#L79" "libs/libc/semaphore/sem_setprotocol.c " _blank
nxmutex_init --> gran_initialize
click nxmutex_init href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L129" "libs/libc/misc/lib_mutex.c " _blank
gran_initialize --> mm_pginitialize
click gran_initialize href "https://github.com/apache/nuttx/blob/master/mm/mm_gran/mm_graninit.c#L148" "mm/mm_gran/mm_graninit.c " _blank
mm_pginitialize --> nx_start
click mm_pginitialize href "https://github.com/apache/nuttx/blob/master/mm/mm_gran/mm_pgalloc.c#L100" "mm/mm_gran/mm_pgalloc.c " _blank
nx_start --> kmm_map_initialize
click nx_start href "https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L600" "sched/init/nx_start.c " _blank
kmm_map_initialize --> up_addrenv_kmap_init
click kmm_map_initialize href "https://github.com/apache/nuttx/blob/master/mm/kmap/kmm_map.c#L283" "mm/kmap/kmm_map.c " _blank
up_addrenv_kmap_init --> mmu_get_base_pgt_level
click up_addrenv_kmap_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv_pgmap.c#L192" "arch/arm64/src/common/arm64_addrenv_pgmap.c " _blank
mmu_get_base_pgt_level --> up_addrenv_kmap_init
click mmu_get_base_pgt_level href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L794" "arch/arm64/src/common/arm64_mmu.c " _blank
up_addrenv_kmap_init --> arm64_pgvaddr
click up_addrenv_kmap_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv_pgmap.c#L204" "arch/arm64/src/common/arm64_addrenv_pgmap.c " _blank
arm64_pgvaddr --> up_addrenv_kmap_init
click arm64_pgvaddr href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/pgalloc.h#L75" "arch/arm64/src/common/pgalloc.h " _blank
up_addrenv_kmap_init --> mmu_ln_getentry
click up_addrenv_kmap_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv_pgmap.c#L212" "arch/arm64/src/common/arm64_addrenv_pgmap.c " _blank
mmu_ln_getentry --> up_invalidate_dcache
click mmu_ln_getentry href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L743" "arch/arm64/src/common/arm64_mmu.c " _blank
up_invalidate_dcache --> arm64_dcache_range
click up_invalidate_dcache href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_cache.c#L509" "arch/arm64/src/common/arm64_cache.c " _blank
arm64_dcache_range --> up_get_dcache_linesize
click arm64_dcache_range href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_cache.c#L154" "arch/arm64/src/common/arm64_cache.c " _blank
up_get_dcache_linesize --> arm64_cache_get_info
click up_get_dcache_linesize href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_cache.c#L552" "arch/arm64/src/common/arm64_cache.c " _blank
arm64_cache_get_info --> up_get_dcache_linesize
click arm64_cache_get_info href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_cache.c#L115" "arch/arm64/src/common/arm64_cache.c " _blank
up_get_dcache_linesize --> arm64_dcache_range
click up_get_dcache_linesize href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_cache.c#L554" "arch/arm64/src/common/arm64_cache.c " _blank
arm64_dcache_range --> mmu_ln_getentry
click arm64_dcache_range href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_cache.c#L161" "arch/arm64/src/common/arm64_cache.c " _blank
mmu_ln_getentry --> mmu_pte_to_paddr
click mmu_ln_getentry href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L758" "arch/arm64/src/common/arm64_mmu.c " _blank
mmu_pte_to_paddr --> up_addrenv_kmap_init
click mmu_pte_to_paddr href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.h#L515" "arch/arm64/src/common/arm64_mmu.h " _blank
up_addrenv_kmap_init --> arm64_pgvaddr
click up_addrenv_kmap_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv_pgmap.c#L206" "arch/arm64/src/common/arm64_addrenv_pgmap.c " _blank
arm64_pgvaddr --> up_addrenv_kmap_init
click arm64_pgvaddr href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/pgalloc.h#L75" "arch/arm64/src/common/pgalloc.h " _blank
up_addrenv_kmap_init --> mmu_ln_getentry
click up_addrenv_kmap_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv_pgmap.c#L212" "arch/arm64/src/common/arm64_addrenv_pgmap.c " _blank
mmu_ln_getentry --> up_invalidate_dcache
click mmu_ln_getentry href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L743" "arch/arm64/src/common/arm64_mmu.c " _blank
up_invalidate_dcache --> arm64_dcache_range
click up_invalidate_dcache href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_cache.c#L509" "arch/arm64/src/common/arm64_cache.c " _blank
arm64_dcache_range --> up_get_dcache_linesize
click arm64_dcache_range href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_cache.c#L154" "arch/arm64/src/common/arm64_cache.c " _blank
up_get_dcache_linesize --> arm64_dcache_range
click up_get_dcache_linesize href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_cache.c#L552" "arch/arm64/src/common/arm64_cache.c " _blank
arm64_dcache_range --> mmu_ln_getentry
click arm64_dcache_range href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_cache.c#L161" "arch/arm64/src/common/arm64_cache.c " _blank
mmu_ln_getentry --> mmu_pte_to_paddr
click mmu_ln_getentry href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L758" "arch/arm64/src/common/arm64_mmu.c " _blank
mmu_pte_to_paddr --> up_addrenv_kmap_init
click mmu_pte_to_paddr href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.h#L515" "arch/arm64/src/common/arm64_mmu.h " _blank
up_addrenv_kmap_init --> mmu_ttbr_reg
click up_addrenv_kmap_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_addrenv_pgmap.c#L206" "arch/arm64/src/common/arm64_addrenv_pgmap.c " _blank
mmu_ttbr_reg --> kmm_map_initialize
click mmu_ttbr_reg href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.h#L391" "arch/arm64/src/common/arm64_mmu.h " _blank
kmm_map_initialize --> gran_initialize
click kmm_map_initialize href "https://github.com/apache/nuttx/blob/master/mm/kmap/kmm_map.c#L286" "mm/kmap/kmm_map.c " _blank
gran_initialize --> kmm_zalloc
click gran_initialize href "https://github.com/apache/nuttx/blob/master/mm/mm_gran/mm_graninit.c#L97" "mm/mm_gran/mm_graninit.c " _blank
kmm_zalloc --> mm_zalloc
click kmm_zalloc href "https://github.com/apache/nuttx/blob/master/mm/kmm_heap/kmm_zalloc.c#L52" "mm/kmm_heap/kmm_zalloc.c " _blank
mm_zalloc --> mm_malloc
click mm_zalloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_zalloc.c#L45" "mm/mm_heap/mm_zalloc.c " _blank
mm_malloc --> free_delaylist
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L170" "mm/mm_heap/mm_malloc.c " _blank
free_delaylist --> up_irq_save
click free_delaylist href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L58" "mm/mm_heap/mm_malloc.c " _blank
up_irq_save --> mm_lock_irq
click up_irq_save href "https://github.com/apache/nuttx/blob/master/arch/arm64/include/irq.h#L349" "arch/arm64/include/irq.h " _blank
mm_lock_irq --> free_delaylist
click mm_lock_irq href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L132" "mm/mm_heap/mm_lock.c " _blank
free_delaylist --> up_irq_restore
click free_delaylist href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L85" "mm/mm_heap/mm_malloc.c " _blank
up_irq_restore --> mm_unlock_irq
click up_irq_restore href "https://github.com/apache/nuttx/blob/master/arch/arm64/include/irq.h#L382" "arch/arm64/include/irq.h " _blank
mm_unlock_irq --> free_delaylist
click mm_unlock_irq href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_lock.c#L146" "mm/mm_heap/mm_lock.c " _blank
mm_malloc --> mm_lock
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L197" "mm/mm_heap/mm_malloc.c " _blank
nxsched_gettid --> mm_lock
click nxsched_gettid href "https://github.com/apache/nuttx/blob/master/sched/task/task_gettid.c#L68" "sched/task/task_gettid.c " _blank
nxmutex_lock --> nxsem_wait
click nxmutex_lock href "https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_mutex.c#L251" "libs/libc/misc/lib_mutex.c " _blank
mm_malloc --> mm_size2ndx
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L214" "mm/mm_heap/mm_malloc.c " _blank
mm_malloc --> mm_addfreechunk
click mm_malloc href "https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_malloc.c#L227" "mm/mm_heap/mm_malloc.c " _blank
```

[Download PDF](nuttx-boot-flow.pdf)

# Unicorn Emulator for Apache NuttX RTOS on Avaota-A1 Arm64 SBC

Read the articles...

-   ["Inside Arm64 MMU: Unicorn Emulator vs Apache NuttX RTOS"](https://lupyuen.org/articles/unicorn3.html)

-   ["(Possibly) Emulate PinePhone with Unicorn Emulator"](https://lupyuen.github.io/articles/unicorn)

-   ["(Clickable) Call Graph for Apache NuttX Real-Time Operating System"](https://lupyuen.github.io/articles/unicorn2)

# Unicorn Exception at sys_call0

Unicorn is stuck at sys_call0. Is syscall supported in Unicorn?

```bash
$ cargo run
...
hook_block:  address=0x40806d4c, size=04, sched_unlock, sched/sched/sched_unlock.c:90:18
call_graph:  nxsched_merge_pending --> sched_unlock
call_graph:  click nxsched_merge_pending href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_mergepending.c#L84" "sched/sched/sched_mergepending.c " _blank
hook_block:  address=0x40806d50, size=08, sched_unlock, sched/sched/sched_unlock.c:92:19
hook_block:  address=0x40806d58, size=08, sys_call0, arch/arm64/include/syscall.h:152:21
call_graph:  sched_unlock --> sys_call0
call_graph:  click sched_unlock href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_unlock.c#L89" "sched/sched/sched_unlock.c " _blank
err=Err(EXCEPTION)
PC=0x40806d60
WARNING: Your register accessing on id 290 is deprecated and will get UC_ERR_ARG in the future release (2.2.0) because the accessing is either no-op or not defined. If you believe the register should be implemented or there is a bug, please submit an issue to https://github.com/unicorn-engine/unicorn. Set UC_IGNORE_REG_BREAK=1 to ignore this warning.
CP_REG=Ok(0)
ESR_EL0=Ok(0)
ESR_EL1=Ok(0)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
call_graph:  sys_call0 --> ***_HALT_***
call_graph:  click sys_call0 href "https://github.com/apache/nuttx/blob/master/arch/arm64/include/syscall.h#L151" "arch/arm64/include/syscall.h " _blank
```

PC 0x40806d60 points to Arm64 SysCall `svc 0`: [nuttx.S](./nuttx/nuttx.S)

```c
sys_call0():
/Users/luppy/avaota/nuttx/include/arch/syscall.h:152
/* SVC with SYS_ call number and no parameters */
static inline uintptr_t sys_call0(unsigned int nbr)
{
  register uint64_t reg0 __asm__("x0") = (uint64_t)(nbr);
    40806d58:	d2800040 	mov	x0, #0x2                   	// #2
/Users/luppy/avaota/nuttx/include/arch/syscall.h:154
  __asm__ __volatile__
    40806d5c:	d4000001 	svc	#0x0
// 0x40806d60 is the next instruction to be executed on return from SysCall
```

Unicorn reports the exception as...
- syndrome=0x86000006
- fsr=0x206
- vaddress=0x507fffff

Based on [ESR-EL1 Doc](https://developer.arm.com/documentation/ddi0601/2025-03/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-)...
- Syndrome / FSR = 6 = 0b000110	
- Meaning "Translation fault, level 2"
- But why halt at sys_call0?
- NuttX seems to be triggering the SysCall for Initial Context Switch, according to the [Call Graph](https://raw.githubusercontent.com/lupyuen/pinephone-emulator/refs/heads/avaota/nuttx-boot-flow.mmd)

![Unicorn Emulator for Avaota-A1 SBC](https://lupyuen.org/images/unicorn3-avaota.jpg)
