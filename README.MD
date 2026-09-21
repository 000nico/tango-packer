<div align="center">

<img src="banner.jpg" alt="blue-pill" width="600">

<br><br>

[![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![language](https://img.shields.io/badge/language-Rust-000000?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![language](https://img.shields.io/badge/language-C-A8B9CC?style=flat-square&logo=c&logoColor=black)](https://en.wikipedia.org/wiki/C_(programming_language))
[![platform](https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com)

**[features](#features) · [docs](docs/) · [contribute](#contribute)**

*PE packer.*

</div>

# Tango Packer

**Tango Packer** is a high-performance Windows PE (Portable Executable) packer and protector designed for runtime executable obfuscation, payload encryption, and anti-analysis research. It manipulates 64-bit PE binaries (x86_64) by encrypting executable code sections, injecting a dependency-free C runtime stub, and restoring original execution flow seamlessly at runtime.

---

## Technical Architecture Overview

Tango Packer is architected into two decoupled components operating at different execution levels:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          1. Packing Phase (Rust)                       │
│                                                                        │
│  [ Target PE Binary ] ──► PE Parser ──► ChaCha20 Encryption Engine     │
│                                                   │                    │
│  [ Output Executable ] ◄── PE Header Restructurer ◄─┴─ Stub Injector   │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       2. Runtime Stub Unpacking (C)                    │
│                                                                        │
│  [ Process Entry Point ] ──► PEB Module Walk & API Hash Resolution      │
│                                           │                            │
│  [ Original Entry Point (OEP) ] ◄── ChaCha20 Decrypt & Memory Protect   │
└────────────────────────────────────────────────────────────────────────┘
```

### 1. The Packer Engine (`Rust`)
Built in safe Rust, the packer operates as an offline binary transformation tool:
* **PE Format Parser**: Custom binary parser designed to decode `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS64`, and `IMAGE_SECTION_HEADER` structures to locate executable sections (`IMAGE_SCN_MEM_EXECUTE`).
* **ChaCha20 Cryptographic Engine**: Implements the **ChaCha20** symmetric stream cipher (256-bit key, 96-bit nonce) to encrypt `.text` and designated executable sections. ChaCha20 ensures high-throughput stream encryption, destroying static byte signatures and disrupting static disassembly.
* **PE Header Restructuring**:
  * Appends a new PE section header (`.stub` / `.tango`) to the target section table.
  * Adjusts section characteristics to `IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE`.
  * Recalculates `SizeOfImage`, section alignment (`SectionAlignment`, `FileAlignment`), and updates `AddressOfEntryPoint` to point directly to the injected stub shellcode.
* **Pattern Patching**: Dynamically injects runtime variables (e.g., Original Entry Point (OEP) relative address and ChaCha20 encryption keys/nonces) into pre-defined signature markers within the stub binary before final PE serialization.

### 2. The Runtime Stub (`Freestanding C`)
The stub is a minimal, position-independent runtime execution unit injected into the host executable:
* **Freestanding Compilation**: Programmed in pure C without standard library bindings (`-nostdlib`, `-nodefaultlibs`, `-ffreestanding`). It leaves no import table entries (IAT) and executes entirely from memory allocated within the host process.
* **Dynamic API Resolution via PEB Traversal**:
  * Locates `kernel32.dll` and `ntdll.dll` base addresses by traversing the Process Environment Block (`PEB -> PPEB_LDR_DATA -> InMemoryOrderModuleList`).
  * Resolves Windows Native APIs (`VirtualProtect`, `VirtualAlloc`, `AddVectoredExceptionHandler`, `NtFlushInstructionCache`) dynamically using **DJB2 / ROR13 API Name Hashing**, eliminating static API strings from the binary.

---

## Core Technical Features & Evasion Techniques

### ChaCha20 Payload Encryption
* Executable code sections (such as `.text`) are encrypted using **ChaCha20** 256-bit stream cipher during the packing process.
* At runtime, the stub initializes the ChaCha20 state matrix, expands the 256-bit key and nonce, and performs in-place stream decryption over the target virtual memory region before executing the payload.

### Vectored Exception Handling (VEH) & Page-on-Demand Decryption
* **Page Protection Manipulation**: Encrypted code sections can be initially set to non-executable memory permissions (`PAGE_NOACCESS` or `PAGE_READONLY`).
* **VEH Access Fault Trapping**: Registers a custom Vectored Exception Handler via `AddVectoredExceptionHandler`. Upon triggering an `EXCEPTION_ACCESS_VIOLATION` (when execution jumps to an encrypted page), the VEH intercepts the exception, dynamically decrypts the target page using ChaCha20, elevates page permissions to `PAGE_EXECUTE_READ`, and resumes normal instruction execution.

### Anti-Debugging & Environment Integrity Checks

### (TO-DO) Custom Instruction Virtual Machine (VM)
* Critical initialization and execution control logic are embedded within a custom instruction VM architecture.
* Replaces native x86_64 instructions with custom bytecode, interpreted dynamically by the stub to prevent straightforward static decompilation and automated reverse engineering tools (e.g., Ghidra, Hex-Rays).

---

## Execution Flow Pipeline

```
1. [Disk] Host Binary Loading
   └─► OS Loader reads PE headers, maps sections, jumps to new Entry Point (Stub).

2. [Memory] Stub Initialization
   ├─► Read PEB to locate Loaded Modules (kernel32.dll / ntdll.dll).
   ├─► Parse Export Address Table (EAT) & Resolve APIs via Hash Matching.
   └─► Execute Anti-Debug & Anti-Analysis Routines.

3. [Memory] Unpacking & Decryption
   ├─► Modify memory page protections via VirtualProtect (PAGE_READWRITE).
   ├─► Execute ChaCha20 stream decryption across target executable sections.
   └─► Restore execution permissions (PAGE_EXECUTE_READ / PAGE_EXECUTE_READWRITE).

4. [Memory] Execution Handover
   └─► Indirect jump to Original Entry Point (OEP) to resume normal binary execution.
```

---

## Building & Compilation

### Prerequisites
* **Rust Toolchain**: `cargo`, `rustc` (Nightly/Stable 2021 edition)
* **MinGW-w64 Cross-Compiler**: `x86_64-w64-mingw32-gcc` (for standalone C stub generation)
* **PowerShell** (Windows) or **Bash** (Linux/macOS)

### 1. Compile the Freestanding Stub Shellcode
Build the pure C stub binary into stripped machine shellcode:

```powershell
# Windows PowerShell
cd src/core/stub_src
.\build_shellcode.ps1
```

```bash
# Linux / macOS Bash
cd src/core/stub_src
chmod +x build_shellcode.sh
./build_shellcode.sh
```

### 2. Build the Rust Packer
Build the main packer CLI application:

```bash
# Return to project root
cd ../../../
cargo build --release
```

The compiled binary will be located at `target/release/packer.exe`.

---

## Usage Syntax

To pack a target 64-bit Windows PE executable:

```cmd
packer.exe <path_to_target.exe>
```

Output:
* Generates `output.exe` in the current working directory.
* The output executable contains the encrypted payload, modified entry point, and embedded C decryption stub.

---

## Research & Educational Disclaimer

This project is strictly developed for **educational, reverse-engineering, and security research purposes**. It serves as an experimental framework to understand binary structures, PE header manipulation, low-level Windows memory management, and anti-analysis mechanisms. The author assumes no responsibility for misuse or unauthorized applications.
