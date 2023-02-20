# Apache NuttX RTOS for PinePhone

See ["Build Apache NuttX RTOS for PinePhone"](https://lupyuen.github.io/articles/lvgl2#appendix-build-apache-nuttx-rtos-for-pinephone)

Apache NuttX RTOS for PinePhone was built with these commands...

```bash
mkdir nuttx
cd nuttx
git clone https://github.com/apache/nuttx nuttx
git clone https://github.com/apache/nuttx-apps apps

cd nuttx
tools/configure.sh pinephone:nsh
make

cp .config nuttx.config
aarch64-none-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  nuttx \
  >nuttx.S \
  2>&1
```

Which produces...

-   [nuttx.bin](nuttx.bin): Binary image for Apache NuttX

    (Address: `0x40080000`, Size: 279 KB)

-   [nuttx.S](nuttx.S): Arm64 Disassembly for Apache NuttX
