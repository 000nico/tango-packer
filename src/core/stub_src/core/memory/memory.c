void jump_to_original_entry_point(volatile unsigned long long address) {
    __asm__ volatile (
        "jmp *%0"
        :
        : "r" (address)
    );
}

unsigned long long get_real_image_base() {
    unsigned long long peb;
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r" (peb));

    unsigned long long image_base = *(unsigned long long*)(peb + 0x10);
    return image_base;
}