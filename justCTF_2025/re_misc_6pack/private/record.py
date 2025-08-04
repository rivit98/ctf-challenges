import subprocess
import threading
import queue
import time
import json
import pexpect
from dataclasses import dataclass
import base64
import zlib

stage2_data = open("./stage2.exe", "rb").read()
chunks = [ stage2_data[i:i+512] for i in range(0, len(stage2_data), 512)]
chunks = [ base64.b64encode(chunk).decode() for chunk in chunks ]

checksum = zlib.crc32(stage2_data) & 0xffffffff
checksum = hex(checksum)

scenario = [
    "c1: hey man how's it going",
    "c2: yo all good just chilling at home",
    "c1: same here been a long day at work",
    "c1: had some pizza and just vibing",
    "c2: nice that sounds chill",
    "c2: i just got done with some coding stuff",
    "c1: cool check this out",
    "c1: i discovered heroes of might and magic 3 and its epic",
    "c2: no way that classic game is so lit",
    "c1: yeah its totally dope and got mad retro vibes",
    "c1: spent the whole night playing and having a blast",
    "c2: omg that is insane i love that nostalgia",
    "c2: remember the days of pixel art and epic battles",
    "c1: exactly its like stepping back in time",
    "c1: the gameplay is tight and the music is fire",
    "c2: for real i get major chill vibes from that game",
    "c2: havent played in ages but now im hyped",
    "c1: we should totally squad up for a game night",
    "c1: thinking of a weekend marathon with the crew",
    "c2: we can invite a few friends and just game all night",
    "c1: hell yeah and we can talk about our coding wins",
    "c1: plus share some dank memes too",
    "c2: omg memes are life",
    "c2: btw did you catch that new tech release",
    "c1: nah been too busy gaming and chilling",
    "c1: caught a bit of it on social tho",
    "c2: same here just skimming news while gaming",
    "c1: love how we can code and game at the same time",
    "c2: preach that its all about balance",
    "c2: work hard play harder right",
    "c1: exactly man its all about good vibes",
    "c1: letting loose when the day is done is the move",
    "c2: totally get that its a lifestyle",
    "c2: gotta run some errands but chatting is fun",
    "c1: no worries catch you later",
    "c1: im off to try a new mod for heroes of might and magic 3",
    "c2: lol that sounds rad have fun",
    "c1: def gonna flex my strategy moves",
    "c2: better check out my brand new flag checker",
    "c2: going to send it in chunks",
    *[f'c2: {chunk}' for chunk in chunks],
    f"c2: uncompressed file checksum crc32: {checksum}",
    "c1: ok, will let you know once I find matching input",
    "c2: cool",
    "c1: brb"
]

# Add project files

@dataclass
class DialogueText:
    person: str
    texts: list[str]

    @property
    def n(self):
        return len(self.texts)


class Dialogue:
    def __init__(self, dialogue):
        self.dialogue = self._prepare_dialogue(dialogue)
        self.current_idx = 0
        self.lock = threading.Lock()

    def _prepare_dialogue(self, dialogue):
        current_texts = []
        current_person = None
        texts = []
        for line in dialogue:
            person, text = line.split(':', maxsplit=1)
            text = text.lstrip()

            if current_person and person != current_person:
                texts.append(DialogueText(current_person, current_texts))
                current_texts = []

            current_person = person
            current_texts.append(text)

        if current_texts:
            texts.append(DialogueText(current_person, current_texts))

        return texts

    def next(self):
        with self.lock:
            self.current_idx += 1

    def current(self):
        with self.lock:
            if self.current_idx < len(self.dialogue):
                return self.dialogue[self.current_idx]

    def __repr__(self):
        return repr(self.dialogue)


class Client:
    def __init__(self, name, rcv_queue, send_queue):
        self.r = rcv_queue
        self.s = send_queue
        self.name = name
        self.t = None

    def run(self, dialogue):
        self.t = threading.Thread(target=self._run, args=(dialogue, ))
        self.t.start()

    def _run(self, dialogue):
        self._spawn()
        self._setup()
        time.sleep(5) # barrier/sema
        self._run1(dialogue)
        self._cleanup()

    def _cleanup(self):
        self.p.terminate()

    def get_ipv6(self):
        output = subprocess.check_output(f'docker network inspect ip6net', shell=True)
        output = json.loads(output.decode('utf8'))
        containers = output[0]['Containers']
        for cid, cd in containers.items():
            if cd['Name'] == self.name:
                return cd["IPv6Address"].split('/')[0]

    def sendline(self, msg):
        self.print('snd', msg)
        self.p.sendline(msg)
        self.readline() # consume my message

    def readline(self):
        return self.p.readline()
    
    def send_msg(self, msg):
        self.s.put(msg)

    def recv_msg(self):
        return self.r.get()
    
    def _spawn(self):
        print(f'spawning client {self.name}')

        self.p = pexpect.spawn(
            f'docker run --network ip6net -it --name {self.name} 6-pack-runner /app/6-pack'
        )

        # consume help text
        for _ in range(4):
            self.p.readline()

        time.sleep(1)
        ipv6 = self.get_ipv6()
        if ipv6 is None:
            raise ValueError('no ipv6 set')
        
        self.ip = ipv6

    def _setup(self):
        self.send_msg(f'!connect {self.ip}')
        cmd = self.recv_msg()
        self.sendline(cmd)

    def print(self, *args):
        print(self.name, *args)

    def _run1(self, scenario):
        while (dialogue := scenario.current()) is not None:
            self.print(dialogue)
            my_turn = dialogue.person == self.name
            for t in dialogue.texts:
                if my_turn:
                    self.sendline(t)
                    time.sleep(3 if len(t) < 10 else 5)
                    
                    self.print('confirmation', self.recv_msg())
                    self.send_msg('wait a bit')
                else:
                    r = self.readline()
                    print(self.name, 'rcv', r)
                    time.sleep(1)
                    self.send_msg(r)    # confirm

                    print(self.name, 'rcv', self.recv_msg())
                    time.sleep(1)

            if my_turn:
                scenario.next()

        self.print('finished')


def main():
    # start tcpdump, scapy

    q1 = queue.Queue()
    q2 = queue.Queue()
    c1 = Client('c1', q1, q2)
    c2 = Client('c2', q2, q1)

    dialogue = Dialogue(scenario)

    cmds = f"""
docker rm -f {c1.name} {c2.name} || true
docker build -t 6-pack-runner -f Dockerfile .
docker network create --opt com.docker.network.bridge.name=ip6net --ipv6 ip6net || true
""".strip()
    
    for cmd in cmds.split("\n"):
        if not cmd: continue
        print(cmd)
        out = subprocess.check_output(cmd, shell=True)

    c1.run(dialogue)
    c2.run(dialogue)

    c1.t.join()
    c2.t.join()



if __name__ == "__main__":
    main()