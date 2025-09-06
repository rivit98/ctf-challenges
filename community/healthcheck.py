#!/usr/bin/env python3

import subprocess
import argparse
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from pathlib import Path

from gen import get_challs

HOST = "rivit.dev"

def solve_task(data):
    task_folder = data.get('dir')
    private_folder = Path(task_folder) / 'private'
    flag_file = data.get("flag", "flag.txt")
    port = data.get('port')
    flag = (private_folder / flag_file).read_text().strip()
    process_args = ['python3', 'solve.py', 'REMOTE']
    output = None
    e=None

    if not args.local:
        process_args.extend([f'HOST={HOST}', f'PORT={port}'])
    else:
        process_args.extend([f'HOST=localhost', f'PORT={port}'])

    outputs = []
    for try_nr in range(1, 6):
        try:
            output = subprocess.check_output(process_args, timeout=120, cwd=private_folder)
            e = output

            if flag.encode() in output:
                return True, output

            if any(x in output for x in [b"CTFlearn"]):
                return False, f"wrong flag\n{output}"

        except subprocess.CalledProcessError as ex:
            e = ex.output
        except Exception as ex:
            e = ex

        outputs.append(e)
        time.sleep(try_nr)
    
    joined_outputs = '\n'.join([str(x) for x in outputs])
    return False, f"failed after {try_nr}\n{joined_outputs}"


def check_tasks(parallelism, tid=None):
    ch = dict(get_challs('./config.yml'))

    if tid is not None:
        ch = [(tid, ch.get(tid))]
    else:
        ch = list(ch.items())

    random.shuffle(ch)

    success, failed = 0, 0
    with ThreadPoolExecutor(min(len(ch), parallelism)) as executor:
        futures = {executor.submit(solve_task, data): (task_name, data) for task_name, data in ch}

        for future in as_completed(futures, timeout=300):
            task_name, data = futures.get(future)
            ok, output = future.result()

            text = f"{task_name} - {'OK' if ok else 'FAILED'}"
            if args.debug or not ok:
                text += f"\n{output}"

            print(text)

            if ok:
                success += 1
            else:
                failed += 1

    print(f"Tasks checked! {success} OK, {failed} FAILED")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Health checker')
    parser.add_argument('--debug', default=False, action='store_true', help='shows output from every solve script, not only failed')
    parser.add_argument('--local', default=False, action='store_true', help='performs healthcheck on localhost')
    parser.add_argument('--task', type=str, metavar='ID', help='test specific task')
    parser.add_argument('--parallelism', type=int, default=10, help='level of parallelism')

    args = parser.parse_args()
    check_tasks(args.parallelism, args.task)
