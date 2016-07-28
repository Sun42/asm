#!/bin/sh
nasmw.exe -f elf shellcode.asm
ld.exe -o pl shellcode.o
objdump.exe -d pl
