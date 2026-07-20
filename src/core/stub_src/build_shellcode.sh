#!/bin/bash

CFLAGS="-Os -fno-ident -fno-asynchronous-unwind-tables -fno-exceptions -fno-unwind-tables -fPIE -m64 -fno-stack-protector -fvisibility=hidden"
CC="x86_64-w64-mingw32-gcc"

mkdir -p build
mkdir -p output

# Build the shellcode components as position independent code
echo "[*] Compiling..."
$CC -c stub.c                        -o build/stub.o          $CFLAGS
$CC -c core/pe/pe.c                  -o build/pe.o            $CFLAGS
$CC -c core/peb/peb.c                -o build/peb.o           $CFLAGS
$CC -c core/crypto/xor.c             -o build/xor.o           $CFLAGS
$CC -c core/memory/memory.c          -o build/memory.o        $CFLAGS
$CC -c core/sdk/strings/strings.c    -o build/strings.o       $CFLAGS
$CC -c core/sdk/io/io.c              -o build/io.o            $CFLAGS
$CC -c core/veh/veh.c                -o build/veh.o           $CFLAGS

echo "[*] Linking..."
$CC -T shellcode.ld build/stub.o build/pe.o build/peb.o build/xor.o build/memory.o build/strings.o build/io.o build/veh.o -o build/shellcode.elf -nostdlib -Wl,--no-seh

echo "[*] Extracting raw shellcode..."
objcopy -O binary -j .text build/shellcode.elf output/shellcode.bin

echo "[+] Done! output/shellcode.bin ($(stat -c %s output/shellcode.bin) bytes)"