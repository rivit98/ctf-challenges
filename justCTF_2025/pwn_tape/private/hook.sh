#!/bin/sh

cat <<EOF >> $nsjail_cfg
mount {
    dst: "/tmp"
    fstype: "tmpfs"
    rw: true
}
EOF

chroot /srv
