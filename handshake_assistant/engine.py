"""Correlate observed pairwise EAPOL exchanges, without guessing missing packets."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import re
import statistics

MAC = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def valid_mac(value: str) -> bool:
    return bool(MAC.fullmatch(value))


@dataclass(frozen=True)
class Packet:
    time: float
    bssid: str
    source: str
    destination: str
    message: int = 0
    replay: int | None = None
    nonce: str = ""
    mic: str = ""
    key_info: int = 0
    channel: int | None = None
    signal: int | None = None
    frame: int = 0
    descriptor: int = 0
    subtype: int | None = None
    akm: int | None = None
    auth_algorithm: int | None = None

    @property
    def station(self):
        return self.destination if self.source == self.bssid else self.source


def nonzero_hex(value, size):
    value = value.replace(":", "")
    return len(value) == size * 2 and bool(re.fullmatch(r"[0-9a-fA-F]+", value)) and int(value, 16) != 0


@dataclass
class Exchange:
    id: int
    bssid: str
    station: str
    started: float
    updated: float
    descriptor: int
    messages: dict[int, Packet] = field(default_factory=dict)
    duplicates: int = 0
    sae_observed: bool = False

    def accepts(self, p: Packet):
        if p.descriptor != self.descriptor or not 0 <= p.time - self.updated <= 15:
            return False
        if self.messages and (p.key_info & 7) != (next(iter(self.messages.values())).key_info & 7):
            return False
        same = self.messages.get(p.message)
        if same:
            return same.replay == p.replay and same.nonce == p.nonce and same.mic == p.mic
        # Never add a new earlier step after a later step. Conservative for reordered files.
        if self.messages and p.message < max(self.messages):
            return False
        m = self.messages
        if p.message == 2 and 1 in m:
            return p.replay == m[1].replay
        if p.message == 3:
            earlier = m.get(1) or m.get(2)
            if earlier and p.replay <= earlier.replay:
                return False
            return 1 not in m or p.nonce == m[1].nonce
        if p.message == 4:
            return 3 in m and p.replay == m[3].replay
        return False

    @property
    def consistent(self):
        m = self.messages
        if set(m) != {1, 2, 3, 4}:
            return False
        return (
            m[1].replay == m[2].replay
            and m[3].replay == m[4].replay
            and m[3].replay > m[1].replay
            and m[1].nonce == m[3].nonce
            and nonzero_hex(m[1].nonce, 32)
            and nonzero_hex(m[2].nonce, 32)
            and all(nonzero_hex(m[i].mic, 16) for i in (2, 3, 4))
            and all(m[i].time <= m[i + 1].time for i in (1, 2, 3))
            and m[4].time - m[1].time <= 15
        )

    def summary(self, redact=False):
        return {
            "id": self.id,
            **({} if redact else {"bssid": self.bssid, "station": self.station}),
            "observed": sorted(self.messages),
            "missing": [i for i in (1, 2, 3, 4) if i not in self.messages],
            "consistent_four_messages": self.consistent,
            "cryptographically_verified": False,
            "duplicates": self.duplicates,
            "key_descriptor_version": next(iter(self.messages.values())).key_info & 7 if self.messages else None,
            "sae_observed": self.sae_observed,
            "duration_seconds": round(self.updated - self.started, 3),
            "descriptor": self.descriptor,
            "frames": {str(i): p.frame for i, p in self.messages.items()},
        }


class Analyzer:
    def __init__(self, target="", max_exchanges=2000):
        if target and not valid_mac(target):
            raise ValueError("Target must be a BSSID such as 02:00:00:00:00:01.")
        self.target = target.lower()
        self.exchanges: deque[Exchange] = deque(maxlen=max_exchanges)
        self.signals = deque(maxlen=1000)
        self.first_time = None
        self.latest_time = None
        self.frames = 0
        self.eapol_frames = 0
        self.ignored = 0
        self.evicted = 0
        self.consistent_count = 0
        self.channels = set()
        self.sae_pairs = deque(maxlen=2000)
        self._next_id = 1
        self._pairs: dict[tuple[str, str], deque[Exchange]] = {}

    def ingest(self, p: Packet):
        if self.target and p.bssid != self.target:
            return
        self.frames += 1
        self.first_time = p.time if self.first_time is None else min(self.first_time, p.time)
        self.latest_time = p.time if self.latest_time is None else max(self.latest_time, p.time)
        if p.channel:
            self.channels.add(p.channel)
        if p.signal is not None:
            self.signals.append(p.signal)
        pair = (p.bssid, p.station)
        if ((p.subtype in (0, 2) and p.akm in (8, 9)) or (p.subtype == 11 and p.auth_algorithm == 3)):
            if valid_mac(p.station) and pair not in self.sae_pairs:self.sae_pairs.append(pair)
        if not p.message:
            return
        self.eapol_frames += 1
        direction_ok = (p.source == p.bssid) if p.message in (1, 3) else (p.destination == p.bssid)
        if (p.message not in (1, 2, 3, 4) or p.replay is None or not p.key_info & 8
                or not valid_mac(p.bssid) or not valid_mac(p.station)
                or int(p.station[:2], 16) & 1 or not direction_ok):
            self.ignored += 1
            return
        pair = (p.bssid, p.station)
        candidates = self._pairs.setdefault(pair, deque(maxlen=32))
        match = next((e for e in reversed(candidates) if e.accepts(p)), None)
        if match is None:
            match = Exchange(self._next_id, p.bssid, p.station, p.time, p.time, p.descriptor)
            self._next_id += 1
            if len(self.exchanges) == self.exchanges.maxlen:
                old = self.exchanges[0]
                self.consistent_count -= int(old.consistent)
                old_pair = (old.bssid, old.station)
                old_candidates = self._pairs.get(old_pair)
                if old_candidates and old in old_candidates:
                    old_candidates.remove(old)
                if old_candidates is not None and not old_candidates:
                    self._pairs.pop(old_pair, None)
                self.evicted += 1
            self.exchanges.append(match)
            self._pairs.setdefault(pair, deque(maxlen=32)).append(match)
        was_consistent = match.consistent
        if p.message in match.messages:
            match.duplicates += 1
        else:
            match.messages[p.message] = p
        match.sae_observed = match.sae_observed or pair in self.sae_pairs
        match.updated = p.time
        if not was_consistent and match.consistent:
            self.consistent_count += 1

    def snapshot(self, redact=False):
        exchanges = [e.summary(redact) for e in self.exchanges]
        return {
            "scope": "Observed WPA-family pairwise EAPOL exchanges; not password or MIC verification",
            "target": "selected access point" if redact and self.target else self.target,
            "frames_observed": self.frames,
            "eapol_frames": self.eapol_frames,
            "ignored_key_frames": self.ignored,
            "retained_exchanges": len(exchanges),
            "evicted_exchanges": self.evicted,
            "consistent_exchanges": sum(e["consistent_four_messages"] for e in exchanges),
            "sae_exchanges": sum(e["sae_observed"] for e in exchanges),
            "unsupported_akm_exchanges": sum(e["key_descriptor_version"] == 0 for e in exchanges),
            "capture_span_seconds": round((self.latest_time or 0) - (self.first_time or 0), 2),
            "channels": sorted(self.channels),
            "median_signal_dbm": statistics.median(self.signals) if self.signals else None,
            "exchanges": exchanges,
        }


def coach(snapshot):
    """Deterministic findings. Never present these as generated AI advice."""
    if not snapshot["frames_observed"]:
        return ["No matching Wi-Fi frames observed. Check the selected BSSID, adapter permissions, monitor mode, and channel before waiting longer."]
    findings = []
    if snapshot.get("sae_exchanges"):
        findings.append("WPA3-SAE authentication was observed for a captured client. Its exchange cannot be used for this WPA/WPA2-PSK offline password recovery. Capture a WPA2-PSK client connection for that test.")
    elif snapshot.get("unsupported_akm_exchanges"):
        findings.append("An AKM-defined key exchange was captured. This key descriptor is unsupported by the Hashcat WPA/WPA2 recovery path; more copies of the same exchange will not make it usable.")
    if snapshot["consistent_exchanges"] and not snapshot.get("unsupported_akm_exchanges"):
        findings.append("A consistent four-message exchange is present. Save the capture; this checks observed structure, not the password or cryptographic validity of MICs.")
    elif not snapshot["eapol_frames"]:
        findings.append("Wi-Fi traffic is visible, but no classified pairwise key exchange is present. A passive capture depends on a client naturally connecting or reconnecting.")
    else:
        best = max(snapshot["exchanges"], key=lambda e: len(e["observed"]), default=None)
        if best and best["missing"]:
            findings.append("Most complete exchange is missing " + ", ".join("M" + str(i) for i in best["missing"]) + ". Keep each connection attempt separate; packets from different attempts cannot fill these gaps.")
        only_ap = all(set(e["observed"]) <= {1, 3} for e in snapshot["exchanges"]) and snapshot["exchanges"]
        only_client = all(set(e["observed"]) <= {2, 4} for e in snapshot["exchanges"]) and snapshot["exchanges"]
        if only_ap or only_client:
            findings.append("Only one side of the exchange has been observed. Try a position with better reception of both devices; missing traffic alone does not establish the cause.")
    if len(snapshot["channels"]) > 1:
        findings.append("Multiple channels appear in this capture. For a single access point, staying on its channel avoids observation gaps from hopping.")
    signal = snapshot["median_signal_dbm"]
    if signal is not None and signal < -75:
        findings.append("Reported median signal is weak (below −75 dBm). Compare a closer adapter position; signal readings vary by hardware.")
    if snapshot["evicted_exchanges"]:
        findings.append("Old exchanges were evicted from the in-memory report. The original capture remains the source of truth.")
    return findings or ["Key traffic was observed but could not be correlated. Inspect frame details and capture completeness."]
