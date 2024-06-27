# really nasty and hacky implementation of q3vm asm
# TODO: use nasm with macros

from pwn import *

OP_UNDEF = lambda: Instr0(0)                    # Error: VM halt
OP_IGNORE = lambda: Instr0(1)                   # No operation
OP_BREAK = lambda: Instr0(2)                    # vm->breakCount++
OP_ENTER = lambda x: Instr1(3, x)               # Begin subroutine
OP_LEAVE = lambda x: Instr1(4, x)               # End subroutine
OP_CALL = lambda: Instr0(5)                     # Call subroutine
OP_PUSH = lambda: Instr0(6)                     # Push to stack
OP_POP = lambda: Instr0(7)                      # Discard top-of-stack
OP_CONST = lambda x: Instr1(8, x)               # Load constant to stack
OP_LOCAL = lambda x: Instr1(9, x)               # Get local variable
OP_JUMP = lambda: Instr0(10)                    # Unconditional jump
OP_EQ = lambda x: Instr1(11, x)                 # Compare integers, jump if equal
OP_NE = lambda x: Instr1(12, x)                 # Compare integers, jump if not equal
OP_LTI = lambda x: Instr1(13, x)                # Compare integers, jump if less-than
OP_LEI = lambda x: Instr1(14, x)                # Compare integers, jump if less-than-or-equal
OP_GTI = lambda x: Instr1(15, x)                # Compare integers, jump if greater-than
OP_GEI = lambda x: Instr1(16, x)                # Compare integers, jump if greater-than-or-equal
OP_LTU = lambda x: Instr1(17, x)                # Compare unsigned integers, jump if less-than
OP_LEU = lambda x: Instr1(18, x)                # Compare unsigned integers, jump if less-than-or-equal
OP_GTU = lambda x: Instr1(19, x)                # Compare unsigned integers, jump if greater-than
OP_GEU = lambda x: Instr1(20, x)                # Compare unsigned integers, jump if greater-than-or-equal
OP_EQF = lambda x: Instr1(21, x)                # Compare floats, jump if equal
OP_NEF = lambda x: Instr1(22, x)                # Compare floats, jump if not-equal
OP_LTF = lambda x: Instr1(23, x)                # Compare floats, jump if less-than
OP_LEF = lambda x: Instr1(24, x)                # Compare floats, jump if less-than-or-equal
OP_GTF = lambda x: Instr1(25, x)                # Compare floats, jump if greater-than
OP_GEF = lambda x: Instr1(26, x)                # Compare floats, jump if greater-than-or-equal
OP_LOAD1 = lambda: Instr0(27)                   # Load 1-byte from memory
OP_LOAD2 = lambda: Instr0(28)                   # Load 2-bytes from memory
OP_LOAD4 = lambda: Instr0(29)                   # Load 4-bytes from memory
OP_STORE1 = lambda: Instr0(30)                  # Store 1-byte to memory
OP_STORE2 = lambda: Instr0(31)                  # Store 2-byte to memory
OP_STORE4 = lambda: Instr0(32)                  # *(stack[top-1]) = stack[top]
OP_ARG = lambda x: Instr1(33, x, converter=p8)  # Marshal argument
OP_BLOCK_COPY = lambda x: Instr1(34, x)         # memcpy
OP_SEX8 = lambda: Instr0(35)                    # Sign-Extend 8-bit
OP_SEX16 = lambda: Instr0(36)                   # Sign-Extend 16-bit
OP_NEGI = lambda: Instr0(37)                    # Negate integer
OP_ADD = lambda: Instr0(38)                     # Add integers (two's complement)
OP_SUB = lambda: Instr0(39)                     # Subtract integers (two's complement)
OP_DIVI = lambda: Instr0(40)                    # Divide signed integers
OP_DIVU = lambda: Instr0(41)                    # Divide unsigned integers
OP_MODI = lambda: Instr0(42)                    # Modulus (signed)
OP_MODU = lambda: Instr0(43)                    # Modulus (unsigned)
OP_MULI = lambda: Instr0(44)                    # Multiply signed integers
OP_MULU = lambda: Instr0(45)                    # Multiply unsigned integers
OP_BAND = lambda: Instr0(46)                    # Bitwise AND
OP_BOR = lambda: Instr0(47)                     # Bitwise OR
OP_BXOR = lambda: Instr0(48)                    # Bitwise eXclusive-OR
OP_BCOM = lambda: Instr0(49)                    # Bitwise COMplement
OP_LSH = lambda: Instr0(50)                     # Left-shift
OP_RSHI = lambda: Instr0(51)                    # Right-shift (algebraic; preserve sign)
OP_RSHU = lambda: Instr0(52)                    # Right-shift (bitwise; ignore sign)
OP_NEGF = lambda: Instr0(53)                    # Negate float
OP_ADDF = lambda: Instr0(54)                    # Add floats
OP_SUBF = lambda: Instr0(55)                    # Subtract floats
OP_DIVF = lambda: Instr0(56)                    # Divide floats
OP_MULF = lambda: Instr0(57)                    # Multiply floats
OP_CVIF = lambda: Instr0(58)                    # Convert to integer from float
OP_CVFI = lambda: Instr0(59)                    # Convert to float from integer

class Label(str):
    def __repr__(self):
        return f'>{self}'

class Instr:
    def __init__(self, func, *args):
        self.func = func
        self.args = list(args)
        self.ip = None

    def __repr__(self):
        if self.ip:
            return f'{self.ip:#x}: {self.func} {self.args}'

        return f'{self.func} {self.args}'

    def convert_args(self):
        return self.args

    def to_bytes(self):
        return flat(p8(self.func), self.convert_args())
    
    def to_unpacked(self):
        return flat(p32(self.func), self.convert_args())


class Instr0(Instr):
    def __init__(self, func):
        super(Instr0, self).__init__(func)

class Instr1(Instr):
    def __init__(self, func, arg, converter=p32):
        super(Instr1, self).__init__(func, arg)
        self.converter = converter

    def convert_args(self):
        if self.converter:
            return self.converter(self.args[0])

        return self.args[0]

class QVM:
    def __init__(self):
        self.vmMagic = 0x12721444           # /**< Bytecode image shall start with VM_MAGIC */
        self.instructionCount = 0           # /**< Number of instructions in .qvm */
        self.codeOffset = 8*4               # /**< Byte offset in .qvm file of .code segment */
        self.codeLength = 0                 # /**< Bytes in code segment */
        self.dataOffset = 0                 # /**< Byte offset in .qvm file of .data segment */
        self.dataLength = 0                 # /**< Bytes in .data segment */
        self.litLength = 0                  # /**< Bytes in strings segment (after .data segment) */
        self.bssLength = 0x1000             # /**< How many bytes should be used for .bss segment */
        self.code = bytes()
        self.data = bytes()
        self.lit = bytes()

    def get_bytes(self):
        return flat(
                self.vmMagic,
                self.instructionCount,
                self.codeOffset,
                self.codeLength,
                self.codeOffset + self.codeLength,
                self.dataLength,
                self.litLength,
                self.bssLength
            , word_size=32) + \
            self.code + \
            self.data + \
            self.lit

    def labelize(self, code):
        # collect labels first
        labels = {}
        seen_instr = 0
        for i, l in enumerate(code):
            if type(l) is Label:
                labels[l] = seen_instr
            else:
                seen_instr += 1

        code = list(filter(lambda inst: type(inst) is not Label, code))

        # replace labels in args with offsets
        for i, inst in enumerate(code):
            inst.ip = i
            for aid, a in enumerate(inst.args):
                if a in labels.keys():
                    inst.args[aid] = labels[a]

        return code

    def set_bytecode(self, code_):
        code = self.labelize(code_)
        self.instructionCount = len(code)
        self.raw_code = code
        code = flat([c.to_bytes() for c in code])
        self.code = code
        self.codeLength = len(self.code)

    def set_data(self, d):
        self.data = bytes(d)
        self.dataLength = len(self.data)

    def set_lit(self, d):
        self.lit = bytes(d)
        self.litLength = len(self.lit)
