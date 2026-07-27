/*
 * Linker script for shellcode stub.
 * Flattens all sections into a single .text blob so objcopy can
 * extract position-independent raw code+data.
 */

ENTRY(stub_main)

SECTIONS
{
    . = 0;

    .text : {
        *(.text .text.*)                /* code            */
        . = ALIGN(16);
        *(.rdata .rdata.* .rdata$*)     /* read-only data (COFF $ groups too) */
        . = ALIGN(16);
        *(.rodata .rodata.*)            /* gcc rodata      */
        . = ALIGN(16);
        *(.data .data.* .data$*)        /* initialized data */
        . = ALIGN(16);
        *(.bss .bss.* .bss$*)           /* zero-init data  */
    }

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.pdata)
        *(.xdata)
        *(.reloc)
        *(.debug*)
    }
}
