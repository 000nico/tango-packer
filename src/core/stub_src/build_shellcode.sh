#!/bin/bash

# Build the shellcode components as position independent code
echo "[*] Compiling..."
x86_64-w64-mingw32-gcc -c stub.c -o stub.o -Os -fno-ident -fno-asynchronous-unwind-tables -fPIE -m64 -fno-stack-protector -fvisibility=hidden
x86_64-w64-mingw32-gcc -c core/pe/pe.c -o pe.o -Os -fno-ident -fno-asynchronous-unwind-tables -fPIE -m64 -fno-stack-protector -fvisibility=hidden
x86_64-w64-mingw32-gcc -c core/memory/peb_walking.c -o peb_walking.o -Os -fno-ident -fno-asynchronous-unwind-tables -fPIE -m64 -fno-stack-protector -fvisibility=hidden
x86_64-w64-mingw32-gcc -c core/cryptography/xor/xor.c -o xor.o -Os -fno-ident -fno-asynchronous-unwind-tables -fPIE -m64 -fno-stack-protector -fvisibility=hidden
x86_64-w64-mingw32-gcc -c core/memory/memory.c -o memory.o -Os -fno-ident -fno-asynchronous-unwind-tables -fPIE -m64 -fno-stack-protector -fvisibility=hidden
x86_64-w64-mingw32-gcc -c core/sdk/strings/strings.c -o strings.o -Os -fno-ident -fno-asynchronous-unwind-tables -fPIE -m64 -fno-stack-protector -fvisibility=hidden

echo "[*] Linking..."
x86_64-w64-mingw32-gcc -T shellcode.ld stub.o pe.o peb_walking.o xor.o memory.o strings.o -o shellcode.exe -nostdlib -Wl,--no-seh

echo "[*] Extracting raw shellcode..."
x86_64-w64-mingw32-objcopy -O binary shellcode.exe output/shellcode.bin

echo "[+] Done! output/shellcode.bin ($(stat -c %s output/shellcode.bin) bytes)"