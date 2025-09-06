#!/usr/bin/env python3

import yaml
from jinja2 import Template
from pathlib import Path


def extend_chall(arg):
    k, ch = arg
    if ch.get('build_args') is None:
        ch['build_args'] = []

    ch['build_args'].append(f'flag_path={ch.get("flag", "flag.txt")}')
    return (k, ch)

def get_challs(file):
    with open(file, "rt") as f:
        ch = yaml.safe_load(f)
        challenges = ch['challenges']
        challenges = list(map(extend_chall, challenges.items()))
        return challenges


def generate_compose_file():
    challenges = get_challs('./config.yml')

    rendered = Template(Path('./docker-compose.yml.jinja').read_text()).render(
        tasks=challenges
    )
    Path('./docker-compose.yml').write_text(rendered)


def gen_yaml():
    from pathlib import Path

    challs = {}
    for chall_dir in filter(lambda p: p.is_dir(), Path('.').iterdir()):
        chall_dir: Path
        if not (chall_dir / "run.sh").exists():
            continue

        port = int((chall_dir / "port").read_text())
        challs[str(chall_dir)] = {
            "port": port,
            "enabled": True,
        }

    with open("config.yml", "wt") as f:
        yaml.dump({"challenges": challs}, f)


if __name__ == "__main__":
    generate_compose_file()
    # gen_yaml()
