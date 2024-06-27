## q3vm

- quake vm pwn [q3vm](https://github.com/jnz/q3vm)
- bug here: https://github.com/jnz/q3vm/blob/master/src/vm/vm.c#L1098

## bug explanation & exploitation
- there is relative write possible in OP_CALL handler
- by manipulating `programStack` variable (via OP_ENTER) we can move our "stack" where we want (relative to where programStack is allocated)
- we control programCounter as it is taken from r0 (opStack)
- programStack can be mmaped so it will land near libc, so we can corrupt libc stuff (mangle secret + `initial` struct used in `run_exit_handlers` func)
- leak could be obtained from uninitialized memory of opStack

