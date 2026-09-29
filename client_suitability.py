"""Check whether a selected AP has a client suitable for WPA/WPA2 recovery."""
import queue
import re
import shutil
import subprocess
import threading
import time
import tkinter as tk
from pathlib import Path


def advertised_modes(security):
    words = set(re.findall(r'[A-Z0-9]+', str(security).upper()))
    return 'WPA2' in words and 'PSK' in words, bool({'SAE','MIXED'} & words)


def connection_status(output):
    fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    if fields.get('wpa_state') != 'COMPLETED':
        return None
    auth = fields.get('key_mgmt', '').upper()
    if 'SAE' in auth:
        mode = 'sae'
    elif auth in ('WPA-PSK', 'WPA-PSK-SHA256', 'WPA2-PSK', 'FT-PSK'):
        mode = 'psk'
    else:
        mode = 'other'
    return fields.get('bssid', '').lower(), mode


def connected_client(target, interfaces, run=subprocess.run):
    """Read actual client auth; never query or return the Wi-Fi password."""
    if not shutil.which('wpa_cli'):
        return None
    for name, info in interfaces.items():
        if info.get('mode') != 'managed' or info.get('ssid') != target.get('essid'):
            continue
        try:
            result = run(['wpa_cli', '-i', name, 'status'], capture_output=True,
                         text=True, timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode:
            continue
        status = connection_status(result.stdout)
        if status and status[0] == target.get('bssid', '').lower():
            return status[1]
    return None


def supported_exchanges(snapshot, bssid):
    """Only key exchanges from a client using the WPA/WPA2 descriptor count."""
    return [exchange for exchange in (snapshot or {}).get('exchanges', ())
            if exchange.get('bssid', '').lower() == bssid.lower()
            and exchange.get('key_descriptor_version') in (1, 2)
            and not exchange.get('sae_observed')
            and exchange.get('observed')]


class ClientSuitability:
    def __init__(self, app):
        self.app = app
        self.confirm_other = tk.BooleanVar(value=False)
        self.target_id = ''
        self.connected_mode = None
        self.checked_at = 0
        self.inflight = False
        self.events = queue.Queue()
        self.generation = 0
        self.last_scan_sample = 0

    def select(self, target):
        target_id = (target or {}).get('bssid', '').lower()
        if target_id != self.target_id:
            self.target_id = target_id
            self.confirm_other.set(False)
            self.connected_mode = None
            self.checked_at = 0
            self.last_scan_sample = 0
            self.inflight = False
            self.generation += 1
        self.check_now()

    def check_now(self):
        target = self.app.selected_target or {}
        wpa2, wpa3 = advertised_modes(target.get('security', ''))
        if not target or not wpa3 or not wpa2 or self.inflight:
            return
        self.inflight = True
        self.checked_at = time.monotonic()
        generation = self.generation
        interfaces = {name: dict(info) for name, info in self.app.interfaces.items()}
        target = dict(target)
        def worker():
            try:mode=connected_client(target, interfaces)
            except Exception:mode=None
            self.events.put((generation, mode))
        threading.Thread(target=worker, daemon=True).start()

    def refresh(self):
        changed = False
        try:
            while True:
                generation, mode = self.events.get_nowait()
                if generation == self.generation:
                    changed = changed or mode != self.connected_mode
                    self.connected_mode = mode
                    self.inflight = False
        except queue.Empty:
            pass
        if changed:
            self.app.sync_workflow_action()
        if self.target_id and time.monotonic() - self.checked_at > 30:
            self.check_now()
        # Reuse the existing bounded local packet analyzer on a general scan.
        # Beacons permit a focused capture, but only actual key exchanges can
        # establish whether the resulting evidence is usable for recovery.
        app = self.app
        if (self.target_id and not app.capture_focused and app.capture_prefix
                and not app.coach_panel.busy and time.monotonic() - self.last_scan_sample > 15):
            path = Path(app.capture_prefix + '-01.cap')
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            if 24 < size < 16 * 1024 * 1024:
                self.last_scan_sample = time.monotonic()
                app.coach_panel.source.set(str(path))
                app.coach_panel.target.set(self.target_id)
                app.coach_panel.analyze(live=True)

    def observed(self):
        snapshot = self.app.coach_panel.current_snapshot()
        return supported_exchanges(snapshot, self.target_id) if self.target_id else []

    def unsuitable_clients(self):
        snapshot = self.app.coach_panel.current_snapshot()
        if not snapshot:return set()
        return {exchange.get('station','').lower() for exchange in snapshot.get('exchanges',())
                if exchange.get('bssid','').lower()==self.target_id
                and (exchange.get('sae_observed') or exchange.get('key_descriptor_version')==0)}

    def complete_record_observed(self):
        return any(exchange.get('consistent_four_messages') for exchange in self.observed())

    def can_capture(self):
        target = self.app.selected_target or {}
        return bool(target and advertised_modes(target.get('security', ''))[0])

    def state(self):
        target = self.app.selected_target or {}
        wpa2, wpa3 = advertised_modes(target.get('security', ''))
        if not target:
            return 'none', ''
        if wpa3 and not wpa2:
            return 'unsupported', 'This access point does not offer WPA2-Personal. Choose a network that supports WPA2-PSK.'
        if wpa2 and not wpa3:
            return 'ready', 'WPA2-Personal is available. Capture a device as it reconnects.'
        if wpa2 and wpa3:
            observed = self.observed()
            if observed:
                if any(exchange.get('consistent_four_messages') for exchange in observed):
                    return 'ready', 'WPA2 key messages were captured from a client on this access point. Stop and check for a usable recovery record.'
                return 'ready', 'WPA2 key messages were observed. Keep listening for the missing messages or reconnect that client.'
            if self.connected_mode == 'psk':
                return 'ready', 'This computer currently uses WPA2-PSK on the selected AP. Reconnect it during capture.'
            if self.confirm_other.get():
                return 'ready', 'Capture only while your other WPA2-PSK device reconnects. A usable record still needs confirmation.'
            snapshot = self.app.coach_panel.current_snapshot()
            if snapshot and snapshot.get('sae_exchanges'):
                return 'needs_client', 'This capture has not yet shown a usable WPA2 exchange. Keep listening for a device connecting with WPA2-PSK.'
            count = len(self.app.observed_clients)
            if count:
                return 'needs_client', f'WPA2-Personal is available and {count} device(s) were seen. Focused capture can identify which reconnect using WPA2-PSK.'
            return 'needs_client', 'WPA2-Personal is available. Start focused capture; a usable record depends on a device connecting with WPA2-PSK.'
        return 'unsupported', 'This access point does not advertise WPA2-Personal. Choose a WPA2-PSK network for this test.'

    def ready(self):
        return self.state()[0] == 'ready'
