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
        *(.rdata .rdata.* .rdata$*)     /* read-only data (COFF $ groups too) */
        *(.rodata .rodata.*)            /* gcc rodata      */
        *(.data .data.* .data$*)        /* initialized data */
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
