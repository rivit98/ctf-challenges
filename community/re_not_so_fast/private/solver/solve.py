import re
import zipfile
import sys
import subprocess


def load_asm():
    output = subprocess.check_output(['objdump', '-D', '-M', 'intel', sys.argv[1]])
    lines = output.splitlines()
    
    init_func = []
    found = False
    for line in lines:
        if found:
            init_func.append(line.decode())

        if b'static_initialization_and_destruction' in line:
            found = True

        elif found and not line.strip():
            found = False
            break
    
    # print('\n'.join(init_func))
    return init_func


def extract_pairs(asm_lines):
    numbers = []
    buffer = []
    started = False
    for line in asm_lines:
        line = line.strip()

        if 'pxor   xmm0,xmm0' in line:
            # pairs data start
            started = True

        elif 'call' in line:
            # pairs data end
            started = False
            numbers.append(buffer)
            buffer = []

        elif started and 'mov    DWORD PTR' in line:
            #  40c0d5:	c7 85 40 e5 ff ff d8 	mov    DWORD PTR [rbp-0x1ac0],0xec5d8
            tokens = line.split(',')
            val = tokens[1].strip()
            buffer.append(int(val, 16))

    # print(numbers)
    numbers = list(filter(len, numbers))
    return numbers


def get_char_data(extracted_numbers):
    chars_data = []
    data_per_char = 3
    for i in range(len(extracted_numbers) // data_per_char):
        chars_data.append(extracted_numbers[data_per_char * i:data_per_char * (i + 1)])

    return chars_data


def expand(data):
    numbers = []
    for i in range(len(data) // 2):
        l, r = data[i * 2:(i + 1) * 2]
        numbers.append(list(range(l, r + 1)))

    flat = [x for xs in numbers for x in xs]
    return flat


def get_min(data):
    return min(data)


def get_sort(data):
    nums = expand(data)
    return sorted(nums)[len(nums) // 2]

def get_avg(data):
    nums = expand(data)
    return sum(nums) // len(nums)

def calc_char(min, sort, avg, idx):
    res = min * sort * 3
    res += idx * 0x2137
    res //= avg
    return res % 0x80


def solve_char(arg):
    idx, char_data = arg
    min_data, sort_data, avg_data = char_data

    c = calc_char(
        get_min(min_data),
        get_sort(sort_data),
        get_avg(avg_data),
        idx
    )

    return chr(c)


def main():
    asm_lines = load_asm()
    extracted_numbers = extract_pairs(asm_lines)
    chars_data = get_char_data(extracted_numbers)

    print(''.join(map(solve_char, enumerate(chars_data))))


if __name__ == '__main__':
    main()
