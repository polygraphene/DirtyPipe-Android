SECTIONS
{
. = 0x2000;
.text : {
stage2.o (.text)
stage2-c.o (.text)
*(.rodata)
*(.rodata.*)
}
.data : {
*(.data)
*(.eh_frame*)
}
.bss : { *(.bss) }

}
