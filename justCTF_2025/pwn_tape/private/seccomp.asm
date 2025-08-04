  A = sys_number
  A == execve ? dead : next
  A == execveat ? dead : next
  A == clone ? dead : next
  A == fork ? dead : next
  A == vfork ? dead : next
  A == ptrace ? dead : ok
ok:
  return ALLOW
dead:
  return KILL

# seccomp-tools asm seccomp.asm -f c_source -a i386
