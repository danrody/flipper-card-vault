#!/usr/bin/env python3
"""Dev helper: drive the Flipper over protobuf RPC (screen capture, buttons, app start).

  fz_rpc.py screen                 print the current screen as ASCII
  fz_rpc.py press KEY [KEY...]     short-press keys (up/down/left/right/ok/back, suffix :long)
  fz_rpc.py start PATH [ARGS]      launch an app
"""

import sys
import time

import serial
from serial.tools import list_ports

KEYS = {"up": 0, "down": 1, "right": 2, "left": 3, "ok": 4, "back": 5}
PRESS, RELEASE, SHORT, LONG = 0, 1, 2, 3


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def field(num, wire, payload):
    key = varint((num << 3) | wire)
    if wire == 0:
        return key + varint(payload)
    return key + varint(len(payload)) + payload


class Rpc:
    def __init__(self):
        port = next(p.device for p in list_ports.comports() if p.vid == 0x0483 and p.pid == 0x5740)
        self.s = serial.Serial(port, 230400, timeout=0.3)
        self.s.write(b"\r")
        time.sleep(0.3)
        self.s.reset_input_buffer()
        self.s.write(b"start_rpc_session\r")
        self.s.read_until(b"\n")
        time.sleep(0.2)
        self.s.reset_input_buffer()
        self.cid = 1
        self.buf = b""

    def send(self, content):
        msg = field(1, 0, self.cid) + content
        self.cid += 1
        self.s.write(varint(len(msg)) + msg)

    def _read_varint(self):
        shift = n = 0
        while True:
            while not self.buf:
                self.buf += self.s.read(1)
            b = self.buf[0]
            self.buf = self.buf[1:]
            n |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return n

    def recv(self):
        n = self._read_varint()
        while len(self.buf) < n:
            self.buf += self.s.read(n - len(self.buf))
        msg, self.buf = self.buf[:n], self.buf[n:]
        return parse(msg)

    def screen(self):
        self.send(field(20, 2, b""))
        deadline = time.time() + 5
        while time.time() < deadline:
            m = self.recv()
            if 22 in m:
                frame = parse(m[22])[1]
                self.send(field(21, 2, b""))
                return frame
        raise TimeoutError("no frame")

    def press(self, key, kind=SHORT):
        k = KEYS[key]
        seq = [PRESS, SHORT, RELEASE] if kind == SHORT else [PRESS, LONG, RELEASE]
        for t in seq:
            self.send(field(23, 2, field(1, 0, k) + field(2, 0, t)))
            self.recv()

    def start(self, name, args=""):
        self.send(field(16, 2, field(1, 2, name.encode()) + field(2, 2, args.encode())))
        return self.recv()


def parse(msg):
    out, i = {}, 0
    while i < len(msg):
        key = 0
        shift = 0
        while True:
            b = msg[i]
            i += 1
            key |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        num, wire = key >> 3, key & 7
        if wire == 0:
            v = shift = 0
            while True:
                b = msg[i]
                i += 1
                v |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            out[num] = v
        elif wire == 2:
            ln = shift = 0
            while True:
                b = msg[i]
                i += 1
                ln |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            out[num] = msg[i : i + ln]
            i += ln
        else:
            raise ValueError(f"wire {wire}")
    return out


def render(frame):
    rows = []
    for y in range(0, 64, 2):
        line = ""
        for x in range(128):
            a = frame[x + (y // 8) * 128] >> (y % 8) & 1
            b = frame[x + ((y + 1) // 8) * 128] >> ((y + 1) % 8) & 1
            line += " ▄▀█"[a * 2 + b]
        rows.append(line.rstrip())
    return "\n".join(rows)


def main():
    r = Rpc()
    cmd = sys.argv[1]
    if cmd == "screen":
        print(render(r.screen()))
    elif cmd == "pixels":
        fr = r.screen()
        y0, y1 = int(sys.argv[2]), int(sys.argv[3])
        for y in range(y0, y1):
            print("".join("#" if fr[x + (y // 8) * 128] >> (y % 8) & 1 else "." for x in range(128)).rstrip("."))
    elif cmd == "press":
        for k in sys.argv[2:]:
            name, _, mod = k.partition(":")
            r.press(name, LONG if mod == "long" else SHORT)
            time.sleep(0.15)
        time.sleep(0.4)
        print(render(r.screen()))
    elif cmd == "start":
        print(r.start(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else ""))
        time.sleep(1.0)
        print(render(r.screen()))


if __name__ == "__main__":
    main()
