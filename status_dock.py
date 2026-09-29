"""Persistent status and bounded, read-only tool output across every view."""
import re
import shlex
import time
import tkinter as tk
from pathlib import Path
from tkinter import ttk


def clean_terminal(value):
    value = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', value)
    value = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', value)
    return ''.join(c for c in value.replace('\r', '\n') if c in '\n\t' or ord(c) >= 32)


class StatusDock(ttk.Frame):
    def __init__(self, app):
        super().__init__(app, padding=(14, 8), style='Card.TFrame')
        self.app = app
        self.state_text = tk.StringVar(value='Idle')
        self.activity = ''
        self.last_capture = ''
        self.last_render = None
        self.source = tk.StringVar(value='Automatic')
        self.auto_source = 'Capture tool'
        self.last_recovery_command = ''
        self.follow = tk.BooleanVar(value=True)
        self.expanded = False
        self.last_prefix = None
        self.last_info_at = 0
        self.file_info = 'No capture file yet.'
        row = ttk.Frame(self, style='Card.TFrame')
        row.pack(fill='x')
        ttk.Style(self).configure('Emergency.TButton',foreground='#b42318',font=('TkDefaultFont',11,'bold'),padding=(12,7))
        self.emergency_button=ttk.Button(row,text='■ Stop all',command=app.stop_all_now,style='Emergency.TButton')
        self.emergency_button.pack(side='right',padx=(10,0))
        self.stop_button = ttk.Button(row, text='Stop capture', command=self.stop, state='disabled')
        self.stop_button.pack(side='right')
        self.size_button = ttk.Button(row, text='⌄ Details', command=self.toggle_size)
        self.size_button.pack(side='right',padx=(0,8))
        state_label = ttk.Label(row, textvariable=self.state_text, style='CardHead.TLabel', wraplength=1100)
        state_label.pack(side='left', fill='x', expand=True)
        state_label.bind('<Configure>', lambda e: state_label.configure(wraplength=max(250, e.width)))
        ttk.Label(self, textvariable=app.capture_feedback.title, style='Card.TLabel').pack(anchor='w', pady=(2, 2))
        app.live_advisor.build(self).pack(fill='x',pady=(0,2))
        bar = ttk.Frame(self, style='Card.TFrame')
        self.details_bar=bar
        ttk.Label(bar, text='Live terminal', style='CardHead.TLabel').pack(side='left')
        ttk.Combobox(bar, textvariable=self.source, values=('Automatic', 'Capture tool', 'Recovery tool', 'Activity'), state='readonly', width=14).pack(side='left', padx=10)
        ttk.Checkbutton(bar, text='Follow output', variable=self.follow).pack(side='left')
        shell = ttk.Frame(self)
        self.details_shell=shell
        self.terminal = tk.Text(shell, height=5, wrap='word', background='#101828', foreground='#d1fadf',
                                insertbackground='white', font=('TkFixedFont', 10), relief='flat',
                                padx=10, pady=6, state='disabled')
        scroll = ttk.Scrollbar(shell, command=self.terminal.yview)
        self.terminal.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        self.terminal.pack(side='left', fill='both', expand=True)
        app.after(250, self.refresh)

    def append_activity(self, message):
        self.activity = (self.activity + clean_terminal(message))[-65536:]

    def capture_output(self, process):
        command = getattr(process, 'command', [])
        output = clean_terminal(getattr(process, 'output', ''))
        header = '$ ' + shlex.join(command) if command else 'Capture controller running'
        self.last_capture = header + '\n' + (output or '[Tool output] No diagnostic messages yet. Packet capture runs in background mode.\n')

    def toggle_size(self):
        self.expanded = not self.expanded
        if self.expanded:
            self.details_bar.pack(fill='x',pady=(6,0))
            self.details_shell.pack(fill='x',pady=(5,0))
        else:
            self.details_bar.pack_forget()
            self.details_shell.pack_forget()
        self.size_button.configure(text='⌃ Hide details' if self.expanded else '⌄ Details')

    def recovery_output(self, recovery):
        process = recovery.hashcat_proc or recovery.estimate_proc
        if process is not None:
            self.last_recovery_command = shlex.join(process.args)
            header = '$ ' + self.last_recovery_command
        elif recovery.job_running:
            header = '[Recovery preparation] ' + recovery.state_var.get()
        else:
            header = ('Last command: ' + self.last_recovery_command if self.last_recovery_command
                      else 'Recovery output appears here when analysis or recovery starts.')
        # Read a bounded tail from the existing recovery log, on the Tk thread.
        output = clean_terminal(recovery.output.get('end-65537c', 'end-1c')).strip()
        status = ' · '.join(variable.get() for variable in
                           (recovery.state_var, recovery.progress_var, recovery.speed_var, recovery.eta_var))
        return header + '\n' + output + '\n[Recovery status] ' + status + '\n[Selected GPU] ' + recovery.device_var.get()

    def stop(self):
        recovery = self.app.recovery_panel
        if recovery.job_running:
            recovery.pause_save()
        else:
            self.app.stop_capture()

    def refresh(self):
        app = self.app
        if app.closing:
            return
        app.observe_emergency_marker()
        self.emergency_button.state(['!disabled'])
        target = app.selected_target or {}
        name = target.get('essid', 'Nearby networks')
        recovery = app.recovery_panel
        active = bool(app.proc)
        if app.emergency_active:
            state='EMERGENCY STOP · work interrupted · '+('waiting for cleanup' if app.proc or app.admin_busy or recovery.job_running else 'ready for a new action')
        elif app.stopping or app.stop_pending:
            state = 'Stopping capture…' if app.stopping else 'Stop requested — finishing the current command…'
        elif app.deauth_inflight:
            state = f'CAPTURING · {name} · reconnect burst running'
        elif recovery.job_running:
            state = f'RECOVERING · {recovery.state_var.get()} · {recovery.progress_var.get()} · {recovery.speed_var.get()} · {recovery.eta_var.get()}'
            if active:state += ' · capture also running'
        elif active:
            elapsed = max(0, int(time.monotonic() - (app.scan_started_at or time.monotonic())))
            state = f'{"CAPTURING" if app.capture_focused else "SCANNING"} · {name} · {elapsed//60:02}:{elapsed%60:02} elapsed'
        elif app.coach_panel.busy or str(recovery.analyze_btn.cget('state')) == 'disabled':
            state = f'ANALYZING · {name} · reading the saved capture'
        elif app.admin_busy:
            state = 'Preparing adapter… complete the system authorization prompt if shown'
        else:
            state = f'IDLE · {name} · {"capture stopped" if app.capture_focused else "ready"}'
        self.state_text.set(state)
        self.stop_button.configure(text='Ⅱ Pause & save' if recovery.job_running else 'Stop requested…' if app.stop_pending or app.stopping else 'Stop capture')
        self.stop_button.state(['!disabled'] if (active or recovery.job_running) and not app.stopping and not app.stop_pending else ['disabled'])
        now = time.monotonic()
        if self.last_prefix != app.capture_prefix:
            self.last_prefix = app.capture_prefix
            self.last_capture = ''
            self.last_info_at = 0
        if now - self.last_info_at >= 1:
            self.last_info_at = now
            try:
                path = Path(app.capture_prefix + '-01.cap')
                stat = path.stat()
                self.file_info = f'Packet file: {stat.st_size:,} bytes · last written {max(0, int(time.time()-stat.st_mtime))}s ago'
            except (TypeError, OSError):
                self.file_info = 'Waiting for the capture tool to write packets.' if active else 'No current capture file.'
        process = app.proc
        if process:
            self.capture_output(process)
        c = app.coach_panel
        snapshot = c.current_snapshot()
        counts = ''
        if snapshot:
            counts = f" · preview: {snapshot['frames_observed']:,} packets, {snapshot['eapol_frames']} EAPOL frames"
        if recovery.job_running:self.auto_source = 'Recovery tool'
        elif active:self.auto_source = 'Capture tool'
        source = self.auto_source if self.source.get() == 'Automatic' else self.source.get()
        if source == 'Activity':
            shown = self.activity or 'Activity messages will appear here.\n'
        elif source == 'Recovery tool':
            shown = self.recovery_output(recovery)
        else:
            shown = (self.last_capture or 'Capture output appears here when capture starts.\n').rstrip() + '\n[Live status] ' + self.file_info + counts + '\n'
            if target:
                shown += f"[Selected AP] {name} · {target.get('bssid', '')} · channel {target.get('channel', '')} · {len(app.observed_clients)} observed device(s)\n"
        shown = shown[-65536:].rstrip()
        key = (source, shown)
        if key != self.last_render:
            self.last_render = key
            position = self.terminal.yview()[0]
            self.terminal.configure(state='normal')
            self.terminal.delete('1.0', 'end')
            self.terminal.insert('end', shown)
            self.terminal.configure(state='disabled')
            if self.follow.get():
                self.terminal.see('end')
            else:
                self.terminal.yview_moveto(position)
        app.after(250, self.refresh)
