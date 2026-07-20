# Tango Packer

Tango Packer is a Windows executable packer being developed to explore and implement various packing and evasion techniques. 

## What is a Packer?

A packer is a tool that takes a standard executable file and compresses, encrypts, or obfuscates its original code and data, wrapping it inside a new executable. When the packed executable is launched, a small piece of code called the **stub** runs first. The stub is responsible for allocating memory, decrypting or decompressing the original payload back into its original form, and then transferring execution to the original entry point. This process is often used to protect intellectual property, reduce file size, or evade static analysis and signature-based detection.

## How Tango Packer Works

Tango Packer takes a target executable and encrypts its sections. It then injects a new section containing the **stub** (the decryption engine) and modifies the executable's headers to set the Entry Point to this new section. When the packed executable is run, the stub gains control first, decrypts the original sections in memory, resolves required imports, and finally jumps to the original program's entry point to resume normal execution.

## Architecture

The project is split into two main components, each leveraging a different language suited for its specific requirements:

* **The Packer (Rust)**: The builder tool that parses the target PE (Portable Executable) file, encrypts its contents, creates the new section for the stub, and reconstructs the PE headers. Rust was chosen for this component due to its memory safety, strong typing, and excellent ecosystem for binary manipulation.
* **The Stub (C)**: The minimal runtime (the newly injected section) embedded into the packed executable. It is programmed in pure C **without any external dependencies** (no standard C runtime or `libc`). C provides fine-grained, low-level control over memory and system calls. It generates very small machine code with no runtime overhead, which is critical for a stub that needs to be stealthy, fast, and directly interact with Windows APIs (like memory protection, exception handlers, and the PEB).

## Features (In Progress)

The packer incorporates advanced protection mechanisms, including:
* **Virtualization**: Employs a custom instruction virtual machine to obfuscate execution flow and logic.
* **Anti-Debug & Anti-Tamper**: Implements techniques to detect debuggers, analysis tools, and prevent binary modifications.
* **Anti-Dump**: Prevents security tools and analysts from dumping the unpacked executable from memory.
* **Vectored Exception Handling (VEH)**: Utilized for on-demand memory page decryption. By initially marking pages as non-executable, the OS throws an access violation (`EXCEPTION_ACCESS_VIOLATION`) upon execution attempt. The VEH handler catches this exception, dynamically decrypts the requested page, grants execution permissions, and resumes execution seamlessly.



## Compilation

To build the project, you must first compile the C stub (shellcode) and then build the Rust packer.

1. **Compile the Stub:** 
   Navigate to the stub source directory and run the build script (requires MinGW-w64):
   ```cmd
   cd src/core/stub_src
   powershell -ExecutionPolicy Bypass -File build_shellcode.ps1
   ```
   *(On Linux/macOS, use `./build_shellcode.sh` instead)*

2. **Build the Packer:**
   Return to the project root and compile the Rust project:
   ```cmd
   cd ../../../
   cargo build --release
   ```

## Usage

To pack an executable, simply pass it as an argument to the compiled packer:

```cmd
packer.exe <file>
```

## Disclaimer

This project is developed for educational and research purposes to better understand how executable packing and reverse engineering work on Windows.
