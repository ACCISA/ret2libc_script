# ret2libc_script

This contains scripts to exploit a buffer overflow using 2 ROP chains. solve.py is manual and solve_auto.py uses more pwntools magic

Make sure to have pwninit 
https://github.com/io12/pwninit

## Notes

Romullus — 9:09 AM
patchelf --set-interpreter ld_file exec_file
parital relro -> GOT is writeable
no pie -> aslr dont affect binary
Romullus — 9:17 AM
setbuf() -> makes abinary work well when using remote or nc
Romullus — 9:53 AM
use pwninit then patcheelf
Romullus — 10:02 AM
< <(echo -e "AAAA\xe0\xf4\x84\xf7\xff\x7f")
Romullus — 10:18 AM
strings -tx libc.so.6 |  grep /bin/sh -> to find /bin/sh
Romullus — 10:45 AM
ROPgadget --binary vuln
Romullus — 10:56 AM
if you want to jump to puts you will jump to puts@plt assuming its used in ur binary
Romullus — 12:20 PM
ni -> dont step into calls
Romullus — 12:33 PM
readelf -s ./libc.so | grep func -> find offset of function if u have libc file
readelf -r file -> relocation table 
stack alginment -> ret to an address to align the stack -> seen in xmm0 
Romullus — 12:48 PM
ret2libc ->

we can checksec the binary to understand what we can/cant do

if the binary is no PIE enabled that there ASLR doesnt affect our binary. However that doest mean it wont affect any shared library that are loaded into memory. (libc will be loaded but will be PIE enabled so ASLR will be in effect)
since binary is no PIE we can use ghidra to get the address of functions to return to to not segfault and have a working rop chain.

we find the bof
we find a way to leak addr
we can leak addr by returning to a gadget that lets us write to rdi (1sft function arg for example)
ROPgadget is a tool for that
we can then craft a payload to write to rdi the got entry for a funciton that was resolved (example puts)
this gives us the address of puts in libc
if we have the correct libc version we can then calculate the base address of libc.
from there any function in libc that we want, we can find by doing (libc_addrs + func_offset)

it most cases we want to call system("/bin/bash")
we can find the string "/bin/sh" inside of libc using strings
strings -tx libc.so | grep /bin/sh, this will give u the offset in libc
so libc_addr + offset will give us the actualy location where the /bin/sh string is
we rewrite a rop chain where we write into RDI the address of /bin/sh and we call the system function we previosuly calculated
note: the system function uses some odd registers which means the stack needs to be aligned. To fix that we can just place a ret instruction (preferably from our binary) to allign the stack before we call the system function
