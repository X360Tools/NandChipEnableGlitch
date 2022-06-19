     ENTRY(_start)
     SECTIONS
     {
        . = 0x800002000001C000;
       .text : { *(.text) }
     }
