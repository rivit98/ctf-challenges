#!/bin/sh

./runner && ./q3vm /tmp/program.qvm
echo $?
