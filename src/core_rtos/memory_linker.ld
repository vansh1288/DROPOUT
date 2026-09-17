MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 512K
    RAM (xrw)   : ORIGIN = 0x20000000, LENGTH = 128K
}

SECTIONS
{
    .text :
    {
        KEEP(*(.isr_vector))
        *(.text*)
        *(.rodata*)
        *(.glue_7)
        *(.glue_7t)
        *(.eh_frame)
        . = ALIGN(4);
        _etext = .;
    } > FLASH

    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > RAM AT > FLASH

    .bss :
    {
        . = ALIGN(4);
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > RAM

    .heap :
    {
        . = ALIGN(4);
        _sheap = .;
        _eheap = .;
    } > RAM

    .stack :
    {
        . = ALIGN(8);
        _sstack = .;
        . = _sstack + 4K;
        _estack = .;
    } > RAM

    _sidata = LOADADDR(.data);
}

ASSERT(_eheap == _sheap, "HEAP USAGE DETECTED - Zero heap policy violated")
ASSERT(_ebss <= ORIGIN(RAM) + LENGTH(RAM), "RAM overflow")

/DISCARD/ :
{
    *(.heap*)
    *(.malloc*)
    *(.calloc*)
}