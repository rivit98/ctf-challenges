#!/bin/sh

set -eu

nonce=$(head -c12 /dev/urandom | base64)
bits=26

cat <<EOF
Send the output of: hashcash -mb${bits} ${nonce}
EOF

if head -1 | hashcash -cqb${bits} -df /dev/null -r "${nonce}"; then
	echo pow ok
	
	/usr/bin/qemu-system-x86_64 \
		-m 128M \
		-kernel $PWD/vmlinuz64 \
		-initrd $PWD/initramfs.cpio.gz \
		-cpu qemu64,+smep,+smap \
		-nographic \
		-no-reboot \
		-monitor /dev/null \
		-snapshot \
		-append 'console=ttyS0 nodhcp noswap norestore panic=-1 oops=panic kaslr kpti=1 quiet user=ctf' \
		-drive file=$PWD/flag.txt,format=raw,if=virtio,readonly
    
	echo $?
else
	echo pow failed
fi
