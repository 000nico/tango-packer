$CC = "x86_64-w64-mingw32-gcc"

# Create output directories
New-Item -ItemType Directory -Force -Path build | Out-Null
New-Item -ItemType Directory -Force -Path output | Out-Null

# Build the shellcode components as position independent code
Write-Host "[*] Compiling..."
$sources = @(
    @("stub.c",                       "build/stub.o"),
    @("core/pe/pe.c",                 "build/pe.o"),
    @("core/peb/peb.c",               "build/peb.o"),
    @("core/crypto/xor.c",            "build/xor.o"),
    @("core/memory/memory.c",         "build/memory.o"),
    @("core/sdk/strings/strings.c",   "build/strings.o"),
    @("core/sdk/io/io.c",             "build/io.o"),
    @("core/veh/veh.c",                "build/veh.o"),
    @("core/antidebug/antidebug.c",    "build/antidebug.o")
)

foreach ($src in $sources) {
    Write-Host "  $CC -c $($src[0]) -o $($src[1])"
    & $CC -c $src[0] -o $src[1] -Os -fno-ident -fno-asynchronous-unwind-tables -fno-exceptions -fno-unwind-tables -fPIE -m64 -fno-stack-protector "-fvisibility=hidden"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to compile $($src[0])" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[*] Linking..."
$objs = @("build/stub.o", "build/pe.o", "build/peb.o", "build/xor.o", "build/memory.o", "build/strings.o", "build/io.o", "build/veh.o", "build/antidebug.o")
& $CC -T shellcode.ld @objs -o build/shellcode.elf -nostdlib "-Wl,--no-seh"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Linking failed" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Extracting raw shellcode..."
& objcopy -O binary -j .text build/shellcode.elf output/shellcode.bin
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] objcopy failed" -ForegroundColor Red
    exit 1
}

$size = (Get-Item output/shellcode.bin).Length
Write-Host "[+] Done! output/shellcode.bin ($size bytes)" -ForegroundColor Green
