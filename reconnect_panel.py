"""Shared, plainly labelled reconnect controls for both AirWatch views."""
import math
import time
from tkinter import ttk


class ReconnectPanel(ttk.LabelFrame):
    def __init__(self, parent, app):
        style=ttk.Style(parent)
        style.configure('Reconnect.TLabelframe',background='white',bordercolor='#d0d5dd')
        style.configure('Reconnect.TLabelframe.Label',background='white',foreground='#182230',font=('TkDefaultFont',11,'bold'))
        super().__init__(parent, text='Reconnect devices (deauth)', padding=12,style='Reconnect.TLabelframe')
        self.app = app
        ttk.Label(self, text='To produce a handshake, reconnect a device to Wi-Fi normally, or send a short disconnect request here.',
                  wraplength=1000, justify='left',style='Card.TLabel').pack(anchor='w')
        row = ttk.Frame(self,style='Card.TFrame')
        row.pack(fill='x', pady=(10, 8))
        self.one = ttk.Radiobutton(row, text='One device', variable=app.deauth_scope, value='client')
        self.one.pack(side='left')
        self.clients = ttk.Combobox(row, textvariable=app.client_var, state='readonly', width=23)
        self.clients.pack(side='left', padx=(8, 18))
        self.all = ttk.Radiobutton(row, text='Whole selected network', variable=app.deauth_scope, value='network')
        self.all.pack(side='left')
        self.send = ttk.Button(row, text='Reconnect device…', command=app.send_deauth)
        self.send.pack(side='right', padx=(10, 0))
        self.status = ttk.Label(self, wraplength=1000, justify='left',style='Card.TLabel')
        self.status.pack(anchor='w')
        self.options = ttk.Frame(self)
        self.toggle = ttk.Button(self, text='More options ▸', command=self.toggle_options)
        self.toggle.pack(anchor='w', pady=(6, 0))
        ttk.Label(self.options, text='Bursts').pack(side='left')
        self.count = ttk.Spinbox(self.options, from_=1, to=5, textvariable=app.deauth_count, width=4)
        self.count.pack(side='left', padx=8)
        ttk.Label(self.options, text='Reason').pack(side='left', padx=(12, 6))
        self.reason = ttk.Combobox(self.options, textvariable=app.deauth_reason, state='readonly', width=43,
            values=('1 · Unspecified', '3 · Station leaving', '7 · Class 3 frame from unauthenticated station'))
        self.reason.pack(side='left')

    def toggle_options(self):
        if self.options.winfo_manager():
            self.options.pack_forget()
            self.toggle.configure(text='More options ▸')
        else:
            self.options.pack(fill='x', pady=(8, 0))
            self.toggle.configure(text='Fewer options ▾')

    def refresh(self):
        app = self.app
        whole = app.deauth_scope.get() == 'network'
        active = bool(app.proc and app.capture_focused and not app.stopping and not app.closing)
        busy = app.admin_busy or app.deauth_dialog is not None
        remaining = max(0, math.ceil(app.deauth_cooldown_until - time.monotonic()))
        unsuitable=app.client_suitability.unsuitable_clients()
        clients=[client for client in app.observed_clients if client not in unsuitable]
        preferred={exchange.get('station','').lower() for exchange in app.client_suitability.observed()}
        clients.sort(key=lambda client:(client not in preferred,client))
        if not whole and app.client_var.get() not in clients:
            app.client_var.set(clients[0] if clients else '')
        self.clients.configure(values=clients, state='disabled' if whole or busy else 'readonly')
        for widget in (self.one, self.all, self.count):
            widget.state(['disabled'] if busy else ['!disabled'])
        self.reason.configure(state='disabled' if busy else 'readonly')
        allowed = active and not busy and not remaining and (whole or app.client_var.get() in clients)
        text = 'Reconnect whole network…' if whole else 'Reconnect device…'
        self.send.configure(text=f'Wait {remaining}s' if remaining and not busy else text)
        self.send.state(['!disabled'] if allowed else ['disabled'])
        if not active:
            status = 'Start a focused capture first. One burst is the default; each send requires your confirmation.'
        elif app.deauth_inflight:
            status = 'Sending the short burst… Capture continues. This command ends within 12 seconds.'
        elif remaining:
            status = f'Capture continues. Wait {remaining} seconds before another burst. Watch Handshake status above.'
        elif whole:
            status = 'May disconnect every device on the selected access point, including this computer. Protected devices may ignore it.'
        elif not clients:
            status = ('No compatible client is available. The device observed so far did not use WPA2-Personal, so it cannot produce the recovery record for this test. '
                      'Keep this capture running and use a device confirmed to connect with WPA2-PSK.' if unsuitable else
                      'No device has been heard on this access point yet. This list fills only when the focused capture receives that device’s Wi-Fi traffic. '
                      'Keep capture running and use one of your devices normally; it will appear here when observed.')
        else:
            status = app.deauth_status.get()
            if not status or status.startswith('Start '):
                status = 'Choose a device, then Reconnect device. Capture keeps running during reconnection.'
        self.status.configure(text=status)
