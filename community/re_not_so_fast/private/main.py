import random
from abc import ABC, abstractmethod
from pathlib import Path
from jinja2 import Template
from multiprocessing import Pool
import sys

from z3 import Solver, BitVecs, sat, Or, Ints

MAX_NUM = 1_000_000


class AbstractCollector(ABC):
    def __init__(self, keep_numbers, x, idx):
        self.fixed_val = x
        self.keep_numbers = keep_numbers
        self.idx = idx

    def get_shuffled(self):
        intervals = self.get()
        if not intervals: return None
        random.shuffle(intervals)
        return intervals

    @abstractmethod
    def get(self):
        pass

    def divide_number(self, num, div):
        return [num // div + (1 if x < num % div else 0) for x in range(div)]

    def check_if_overlaps(self, to_check, intervals):
        start, end = to_check
        return any(start in range(s, e + 1) for s, e in intervals) or any(
            end in range(s, e + 1) for s, e in intervals)

    def expand_intervals(self, intervals):
        test = []
        for s, e in intervals:
            test.extend(list(range(s, e + 1)))

        return sorted(test)


class AvgCollector(AbstractCollector):
    def get(self):
        intervals_num = max(self.idx // 10, 3)

        solver = Solver()
        intervals_vars = []
        total_intervals_length = 0
        total_intervals_sum = 0
        for i in range(intervals_num):
            s,e,l = Ints(f"is{i} ie{i} il{i}")
            solver.add(s < e)
            solver.add(e < 2 ** 28)
            solver.add(s < 2 ** 28)
            solver.add(s > 10)
            solver.add(e > 10)
            solver.add(l > 5)
            solver.add(l < 100_000)
            solver.add(e-s+1 == l)
            total_intervals_length += l
            total_intervals_sum += l * ((s + e) / 2)
            intervals_vars.append((s,e,l))

        for i in range(intervals_num-1):
            s1,_,_ = intervals_vars[i]
            s2,_,_ = intervals_vars[i+1]
            solver.add(s1 < s2)

        solver.add(total_intervals_length == self.keep_numbers)
        solver.add(total_intervals_sum == self.fixed_val * self.keep_numbers)
        solver.check()
        mdl = solver.model()

        intervals = []
        for s, e, l in intervals_vars:
            intervals.append((mdl[s].as_long(), mdl[e].as_long()))

        expanded = self.expand_intervals(intervals)
        assert sum(expanded) // len(expanded) == self.fixed_val
        assert len(expanded) == self.keep_numbers
        return list(intervals)


class SortCollector(AbstractCollector):
    def get(self):
        intervals = set()
        # [1,2,3,4,x,8,9,10]   # keep_numbers=8, target_index=4
        target_index = self.keep_numbers // 2
        numbers_before = target_index
        numbers_after = self.keep_numbers - target_index - 1
        intervals_num = max(self.idx // 10, 3)
        first_interval_len = round(self.keep_numbers * (1 / intervals_num))
        intervals_num -= 3  # make sure that one is before, one after and one contains fixed_val
        chances = [random.getrandbits(1) for _ in range(intervals_num)]
        intervals_before = 1 + chances.count(1)
        intervals_after = 1 + chances.count(0)

        first_interval_before = random.randint(0, first_interval_len - 1)
        first_interval_after = first_interval_len - first_interval_before - 1
        target_interval_start = self.fixed_val - first_interval_before
        target_interval_end = self.fixed_val + first_interval_after
        intervals.add((target_interval_start, target_interval_end))
        numbers_before -= first_interval_before
        numbers_after -= first_interval_after

        intervals_before_lengths = self.divide_number(numbers_before, intervals_before)
        intervals_after_lengths = self.divide_number(numbers_after, intervals_after)
        for ilen in intervals_before_lengths:
            success = False
            while not success:
                end = random.randint(ilen + 1, target_interval_start)
                start = end - ilen + 1
                if self.check_if_overlaps((start, end), intervals): continue

                intervals.add((start, end))
                success = True

        for ilen in intervals_after_lengths:
            success = False
            while not success:
                start = random.randint(target_interval_end + 1, MAX_NUM)
                end = start + ilen - 1
                if self.check_if_overlaps((start, end), intervals): continue

                intervals.add((start, end))
                success = True

        expanded = self.expand_intervals(intervals)
        assert expanded[target_index] == self.fixed_val
        assert len(expanded) == self.keep_numbers
        return list(intervals)


class MinCollector(AbstractCollector):
    def get(self):
        intervals = set()
        intervals_after = max(self.idx // 10, 3)
        first_interval_len = round(self.keep_numbers * (1 / intervals_after))
        intervals_after -= 1

        first_interval_after = first_interval_len - 1
        target_interval_start = self.fixed_val
        target_interval_end = self.fixed_val + first_interval_after
        intervals.add((target_interval_start, target_interval_end))
        numbers_after = self.keep_numbers - first_interval_len

        intervals_after_lengths = self.divide_number(numbers_after, intervals_after)
        for ilen in intervals_after_lengths:
            success = False
            while not success:
                start = random.randint(target_interval_end + 1, MAX_NUM)
                end = start + ilen - 1
                if self.check_if_overlaps((start, end), intervals): continue

                intervals.add((start, end))
                success = True

        expanded = self.expand_intervals(intervals)
        assert len(expanded) == self.keep_numbers
        assert expanded[0] == self.fixed_val
        return list(intervals)


class MaxCollector(AbstractCollector):
    def get(self):
        intervals = set()
        intervals_before = max(self.idx // 10, 3)
        first_interval_len = round(self.keep_numbers * (1 / intervals_before))
        intervals_before -= 1

        first_interval_before = first_interval_len - 1
        target_interval_start = self.fixed_val - first_interval_before
        target_interval_end = self.fixed_val
        intervals.add((target_interval_start, target_interval_end))
        numbers_before = self.keep_numbers - first_interval_len

        intervals_before_lengths = self.divide_number(numbers_before, intervals_before)
        for ilen in intervals_before_lengths:
            success = False
            while not success:
                end = random.randint(ilen + 1, target_interval_start)
                start = end - ilen + 1
                if self.check_if_overlaps((start, end), intervals): continue

                intervals.add((start, end))
                success = True

        expanded = self.expand_intervals(intervals)
        assert len(expanded) == self.keep_numbers
        assert expanded[-1] == self.fixed_val
        return list(intervals)


def func(a, b, c, i):
    result = a * b * 3
    result += i * 0x2137
    if isinstance(c, int):
        result //= c
    else:
        result /= c
    result %= 0x80
    return result


def ramper(start, inc, idx):
    if idx < 8:
        return start * (idx + 1)

    if 8 <= idx <= 24:
        return idx * 2 * inc

    if 24 < idx <= 45:
        return idx * 3 * inc

    return idx * 4 * inc


def intervals_len(intervals):
    sum = 0
    for s, e in intervals:
        sum += e - s + 1

    return sum


def solve_char(arg):
    i, needed_idx = arg
    # print(f"Analyzing {i} - needed {needed_idx} {chr(needed_idx)}")

    from_min, from_sort, avg = BitVecs('from_min from_sort from_avg', 64)
    s = Solver()
    s.add(func(from_min, from_sort, avg, i) == needed_idx)
    s.add(avg > 200_000, avg < 400_000)
    s.add(from_min < 300_000, from_min > 10_000)
    s.add(from_sort > 200_000, from_sort < 800_000)

    while s.check() == sat:
        m = s.model()
        fmin = m[from_min].as_long()
        fsort = m[from_sort].as_long()
        favg = m[avg].as_long()
        s.add(Or(from_min != fmin, from_sort != fsort, avg != favg))

        # print(fmin, fsort, e)
        if func(fmin, fsort, favg, i) != needed_idx: continue

        fmin_intervals = MinCollector(ramper(100, 2000, i), fmin, i).get_shuffled()
        fsort_intervals = SortCollector(ramper(50, 100, i), fsort, i).get_shuffled()
        d_intervals = AvgCollector(ramper(100, 300, i), favg, i).get_shuffled()

        # fmin_intervals = MinCollector(ramper(20, 0, i), fmin, i).get_shuffled()
        # fmax_intervals = MaxCollector(ramper(20, 0, i), fmax, i).get_shuffled()
        # fsort_intervals = SortCollector(ramper(20, 0, i), fsort, i).get_shuffled()
        # d_intervals = XorCollector2(ramper(20, 0, i), favg, i).get_shuffled()

        if any(x is None for x in [fmin_intervals, fsort_intervals, d_intervals]):
            print(f"{i} looking for different solution")
            continue

        intervals = [fmin_intervals, fsort_intervals, d_intervals]
        picked_numbers = [fmin, fsort, favg]
        break
    else:
        return None, None

    return intervals, picked_numbers


def get_lengths(*intervals):
    l = []
    for i in intervals:
        l.append(intervals_len(i))

    return ' '.join(map(str, l))


# def test():
#     d_intervals = AvgCollector(ramper(20, 0, 0), 456, 0).get_shuffled()
#     print(d_intervals)


if __name__ == '__main__':
    flag = sys.argv[1]
    platform = sys.argv[2]
    print(f'flag: {flag} {len(flag)} chars')
    needed_indices = list(map(ord, flag))

    challenge_data = []
    picked_numbers = []
    with Pool(8) as pool:
        for i, (intervals, selected_numbers) in enumerate(pool.imap(solve_char, enumerate(needed_indices))):
            if intervals is None or selected_numbers is None:
                raise SystemExit(f"No solution for {i}")

            print(f'{i}. {get_lengths(*intervals)}')
            challenge_data.append(intervals)
            picked_numbers.append(selected_numbers)

    with open(f"src/chall_data_{platform}.hpp", "wt") as f:
        f.write(Template(Path("chall_data.jinja2").read_text()).render(
            challenge_data=challenge_data
        ))

    with open(f"src/verify_data_{platform}.hpp", "wt") as f:
        f.write(Template(Path("chall_verify.jinja2").read_text()).render(
            picked_numbers=picked_numbers
        ))
