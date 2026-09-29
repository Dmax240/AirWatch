"""Shared capture status and a nonblocking, once-per-capture notification."""
import tkinter as tk
from tkinter import ttk


class CaptureFeedback:
    def __init__(self, app):
        self.app = app
        self.title = tk.StringVar(value='Handshake: waiting for capture')
        self.detail = tk.StringVar(value='Select your network, then start a focused capture.')
        self.session = None
        self.level = 0
        self.notified = set()
        self.dialog = None
        self.labels = []

    def build(self, parent):
        card = ttk.Frame(parent, style='Card.TFrame', padding=12)
        label = ttk.Label(card, textvariable=self.title, style='CardHead.TLabel')
        label.pack(anchor='w')
        self.labels.append(label)
        detail = ttk.Label(card, textvariable=self.detail, style='Card.TLabel',
                           wraplength=1000, justify='left')
        detail.pack(fill='x', pady=(5, 0))
        detail.bind('<Configure>', lambda e: detail.configure(wraplength=max(250, e.width)))
        return card

    def dismiss(self):
        if self.dialog is not None:
            self.dialog.destroy()
            self.dialog = None

    def stop(self):
        self.dismiss()
        self.app.after_idle(self.app.stop_capture)

    def update(self, ready_prefix=None):
        app = self.app
        target = app.selected_target or {}
        session = (app.capture_prefix, target.get('bssid', '').lower())
        active = bool(app.proc and app.capture_focused)
        if session != self.session:
            self.dismiss()
            self.session = session
            self.level = 0
            self.notified.clear()
            self.title.set('Handshake: waiting for a device to reconnect')
            self.detail.set('Connect one of your devices to this network.')
        if not app.capture_focused:
            self.title.set('Handshake: start a focused capture')
            self.detail.set('Choose a network, then start capture.')
            return
        c = app.coach_panel
        snapshot = c.current_snapshot()
        level = 0
        if snapshot:
            complete = [e for e in snapshot.get('exchanges', [])
                        if e.get('consistent_four_messages') and e.get('bssid', '').lower() == session[1]]
            if snapshot.get('eapol_frames'):
                level = 1
            if complete:
                level = 2
                if all(e.get('sae_observed') or e.get('key_descriptor_version') == 0 for e in complete):
                    level = 3
        if ready_prefix and ready_prefix == app.capture_prefix:
            level = 4
        if level > self.level:
            self.level = level
            if level == 1:
                self.title.set('Handshake: some messages received')
                self.detail.set('Still looking for a complete record.')
            elif level == 2:
                self.title.set('Handshake captured — checking recovery support')
                self.detail.set('Checking whether this record can be used…')
            elif level == 3:
                self.title.set('Exchange captured — not usable for WPA2 recovery')
                self.detail.set('Try a device using WPA2-Personal.')
            else:
                self.title.set('Handshake captured — ready for recovery')
                self.detail.set('Capture will stop and save this record.')
        color = '#067647' if self.level == 4 else '#b54708' if self.level == 3 else '#175cd3'
        for label in self.labels:
            label.configure(foreground=color)
        if not active:
            self.dismiss()
            if not self.level:
                self.title.set('Handshake: none confirmed in this capture')
                self.detail.set('Try another capture. Your saved files are still here.')
            return
