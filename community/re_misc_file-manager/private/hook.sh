#!/bin/sh

cat <<EOF >> $nsjail_cfg
mount {
    dst: "/tmp"
    fstype: "tmpfs"
    rw: true
}

envar: "FS_PATH=/tmp/fs"
EOF
