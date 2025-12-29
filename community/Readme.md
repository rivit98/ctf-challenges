# Community challenges

This directory contains challenges I have created for various programming communities. Each challenge is designed to test and improve your CTF skills in a fun and engaging way.

## Running challenges locally

Each challenge comes with a Dockerfile that allows you to build and run the challenge in a containerized environment. This ensures that you have a consistent setup regardless of your host system (not really true, but enough for my challenges).

To build and run a challenge, navigate to the challenge directory and use the following commands:

```bash
docker compose --profile enabled up -d
```

Then connect to the selected challenge:

```bash
nc localhost <port>
```
for example:

```bash
(ctf)  ✘ rivit@crag  ~/workspace/github/my-ctf-challs/community  nc localhost 10003
What is your favorite format tag? 
```

## Stats

I stopped hosting community challenges on 30.12.2025 due to time constraints and raising maintenance costs. These are the stats as of that date:

| Challenge name            | Solves |
|---------------------------|--------|
| Accumulator               | 1077   |
| Zippy.zip                 | 689    |
| Leak me                   | 442    |
| Domain name resolver      | 344    |
| Positive challenge        | 326    |
| Impossible equation       | 207    |
| Glob                      | 129    |
| Two times sixteen         | 95     |
| Readme                    | 93     |
| Cookies                   | 85     |
| Runner                    | 69     |
| Random malloc             | 67     |
| Lottery                   | 51     |
| Disabled service          | 48     |
| No more cookies           | 47     |
| secret                    | 44     |
| Buffer brothers           | 39     |
| Patcher                   | 38     |
| Chain                     | 37     |
| Theft                     | 30     |
| Hook                      | 28     |
| school                    | 28     |
| Redirected                | 24     |
| slope                     | 24     |
| Callsys                   | 21     |
| Slow bin                  | 21     |
| Management                | 20     |
| Old times                 | 20     |
| Banned bytes              | 19     |
| Inspector gadget          | 19     |
| House                     | 18     |
| Not so fast               | 16     |
| eraser                    | 12     |
| quack3                    | 12     |
| file manager              | 4      |

