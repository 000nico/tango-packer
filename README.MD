# Tango Packer

Tango Packer is a Windows executable packer being developed to explore and implement various packing and evasion techniques. 

## Architecture

The project is split into two main components, each leveraging a different language suited for its specific requirements:

* **The Packer (Rust)**: The builder tool that takes the target executable and packs it. Rust was chosen for this component due to its memory safety, strong typing, and excellent ecosystem for binary manipulation. It allows for writing robust and complex build logic without the common pitfalls of memory corruption.
* **The Stub (C)**: The minimal runtime injected into the packed executable. C is used for the stub because it provides fine-grained, low-level control over memory and system calls. It generates very small machine code with no runtime overhead, which is critical for a stub that needs to be stealthy, fast, and directly interact with Windows APIs (like memory protection and exception handlers).

## Disclaimer

This project is developed for educational and research purposes to better understand how executable packing and reverse engineering work on Windows.
