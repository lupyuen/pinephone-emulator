# Apache NuttX RTOS for PinePhone

See the articles...

-   ["NuttX RTOS for PinePhone: What is it?"](https://lupyuen.github.io/articles/what)

-   ["Build Apache NuttX RTOS for PinePhone"](https://lupyuen.github.io/articles/lvgl2#appendix-build-apache-nuttx-rtos-for-pinephone)

Apache NuttX RTOS for PinePhone was built with...

```bash
## Download NuttX Source Code
mkdir nuttx
cd nuttx
git clone https://github.com/apache/nuttx nuttx
git clone https://github.com/apache/nuttx-apps apps

## Configure NuttX for PinePhone NSH Minimal Build
cd nuttx
tools/configure.sh pinephone:nsh

## Build NuttX
make

## Save the Build Config
cp .config nuttx.config

## Generate the Arm64 Disassembly
aarch64-none-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  nuttx \
  >nuttx.S \
  2>&1
```

Which produces...

-   [nuttx.bin](nuttx.bin): Binary Image for Apache NuttX RTOS

    (Address: `0x4008` `0000`, Size: 279 KB)

-   [nuttx.S](nuttx.S): Arm64 Disassembly for Apache NuttX RTOS

-   [nuttx](nuttx): ELF Image for Apache NuttX RTOS

-   [nuttx.map](nuttx.map): Linker Map for Apache NuttX RTOS

-   [nuttx.config](nuttx.config): Build Configuration for Apache NuttX RTOS
