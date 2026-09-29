"""Bounded subprocess capture and streaming TShark decoding."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import csv
import os
from pathlib import Path
import re
import signal
import subprocess
import threading

from .engine import Packet, valid_mac

FIELDS = ["frame.time_epoch", "wlan.bssid", "wlan.sa", "wlan.da",
          "wlan_rsna_eapol.keydes.msgnr", "eapol.keydes.replay_counter",
          "wlan_rsna_eapol.keydes.nonce", "wlan_rsna_eapol.keydes.mic",
          "wlan_rsna_eapol.keydes.key_info", "wlan_radio.channel",
          "radiotap.dbm_antsignal", "frame.number", "eapol.keydes.type", "wlan.fc.type_subtype", "wlan.rsn.akms.type", "wlan.fixed.auth.alg"]


def integer(text, default=None):
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except (ValueError, TypeError):
        return default


def decode_line(line):
    cells = next(csv.reader([line], delimiter="\t", quotechar='"'))
    if len(cells) != len(FIELDS):
        raise ValueError("Unexpected TShark output; field count does not match.")
    return Packet(float(cells[0]), cells[1].lower(), cells[2].lower(), cells[3].lower(),
                  integer(cells[4], 0), integer(cells[5]), cells[6].replace(":", "").lower(),
                  cells[7].replace(":", "").lower(), integer(cells[8], 0),
                  integer(cells[9]), integer(cells[10]), integer(cells[11], 0),
                  integer(cells[12], 0), integer(cells[13]), integer(cells[14]), integer(cells[15]))


def field_options():
    return ["-n", "-l", "-T", "fields", "-E", "separator=/t", "-E", "quote=d",
            "-E", "occurrence=f"] + [item for f in FIELDS for item in ("-e", f)]


def wireless_interfaces():
    result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Could not list wireless interfaces.")
    interfaces = []
    current = None
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if parts[:1] == ["Interface"]:
            current = {"name": parts[1], "mode": "unknown", "channel": "—", "frequency": ""}
            interfaces.append(current)
        elif current and parts[:1] == ["type"]:
            current["mode"] = parts[1]
        elif current and parts[:1] == ["channel"]:
            current["channel"] = parts[1]
            current["frequency"] = parts[2].lstrip("(") if len(parts) > 2 else ""
    return interfaces


@dataclass
class LivePipeline:
    producer: list[str]
    decoder: list[str]


def live_command(interface, target, output, duration=300, max_mb=100, frequency=None):
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,64}", interface):
        raise ValueError("Choose a valid wireless interface.")
    if not valid_mac(target):
        raise ValueError("Enter the BSSID of the access point you are testing.")
    if not 5 <= duration <= 3600 or not 1 <= max_mb <= 2048:
        raise ValueError("Duration must be 5–3600 seconds; file limit must be 1–2048 MB.")
    if frequency is not None and not 2300 <= frequency <= 7125:
        raise ValueError("Enter the access point frequency in MHz, for example 2412 or 5180.")
    producer = ["dumpcap", "-i", interface, "-I", "-f", "wlan host " + target.lower(),
            "-a", f"duration:{duration}", "-a", f"filesize:{max_mb * 1024}",
            "-B", "16", "-w", "-"]
    if frequency is not None:
        producer += ["-k", str(frequency)]
    return LivePipeline(producer, ["tshark", "-r", "-", "-w", str(output), "-P"] + field_options())


class CaptureRunner:
    def __init__(self):
        self.process = None
        self.producer = None
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.errors = deque(maxlen=40)

    def run(self, command, on_packet):
        # Own process group lets cancellation stop both TShark and its dumpcap child.
        with self.lock:
            if self.stopped.is_set():
                return
            if isinstance(command, LivePipeline):
                self.producer = subprocess.Popen(command.producer, stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE, start_new_session=True)
                try:
                    self.process = subprocess.Popen(command.decoder, stdin=self.producer.stdout,
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                    text=True, encoding="utf-8", errors="replace",
                                                    bufsize=1, start_new_session=True)
                except Exception:
                    self.producer.kill()
                    self.producer.wait()
                    raise
                finally:
                    self.producer.stdout.close()
            else:
                self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                text=True, encoding="utf-8", errors="replace",
                                                bufsize=1, start_new_session=True)
        process = self.process
        def drain_errors(stream):
            for line in stream:
                if isinstance(line, bytes):
                    line = line.decode("utf-8", "replace")
                self.errors.append(line.rstrip())
        drains = []
        for child in (process, self.producer):
            if child:
                drain = threading.Thread(target=drain_errors, args=(child.stderr,), daemon=True)
                drain.start()
                drains.append(drain)
        try:
            for line in process.stdout:
                if self.stopped.is_set():
                    continue
                if line.strip():
                    on_packet(decode_line(line))
            code = process.wait(timeout=5)
            producer_code = self.producer.wait(timeout=3) if self.producer else 0
            for drain in drains:
                drain.join(timeout=1)
            if (code or producer_code) and not self.stopped.is_set():
                raise RuntimeError("\n".join(self.errors) or f"TShark exited with status {code}.")
        finally:
            if process.poll() is None or (self.producer and self.producer.poll() is None):
                self.stop()
            process.stdout.close()
            process.stderr.close()
            if self.producer:
                self.producer.stderr.close()

    def stop(self):
        self.stopped.set()
        with self.lock:
            process = self.process
        first = self.producer or process
        if first and first.poll() is None:
            try:
                os.killpg(first.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
        for child in (self.producer, process):
            if not child:
                continue
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=2)
            except ProcessLookupError:
                pass


def read_capture(path, on_packet, runner=None):
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError("Capture file does not exist.")
    (runner or CaptureRunner()).run(["tshark", "-r", str(path), "-Y", "wlan"] + field_options(), on_packet)
