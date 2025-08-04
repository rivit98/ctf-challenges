from subprocess import check_output, CalledProcessError
from solve import ff_runner
from multiprocessing import Pool

def slowrun(n):
    try:
        ret = check_output(f"./slowrun {n}", encoding="utf-8", shell=True, cwd='.')
        ret = ret.split("\n")
        ret = ret[-2].removeprefix("flag: ").strip()
        return int(ret)
    except CalledProcessError as e:
        print(e)
        print(e.output)
        return None



def pysolve(n):
    return ff_runner(n)


def tc(n):
    return (n, pysolve(n), slowrun(n))


def main():
    with Pool(4) as p:
        for result in p.imap(tc, range(0, 50)):
            n, pysolve_result, slowrun_result = result
            print(f"n={n} : {pysolve_result} == {slowrun_result}", flush=True)
            assert pysolve_result == slowrun_result, f"Mismatch for n={n}: {pysolve_result} != {slowrun_result}"



if __name__ == "__main__":
    main()