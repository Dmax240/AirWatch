#!/usr/bin/env python3
"""AirWatch: a small Tkinter front end for authorized passive Aircrack-ng captures."""
import csv
import os
import shutil
import signal
import subprocess
import re
import time
import threading
import queue
import uuid
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox, font as tkfont
from recovery import RecoveryPanel
from admin_session import AdminSession, CaptureProcess
from coach_panel import CoachPanel
from guided_view import GuidedView
from capture_feedback import CaptureFeedback
from reconnect_panel import ReconnectPanel
from status_dock import StatusDock
from live_advice import LiveAdvisor
from client_suitability import ClientSuitability

APP = "AirWatch"
Airodump = shutil.which("airodump-ng") or "/usr/sbin/airodump-ng"
Airmon = shutil.which("airmon-ng") or "/usr/sbin/airmon-ng"
Pkexec = shutil.which("pkexec")

class AirWatch(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AirWatch — Capture, Evidence & Recovery")
        screen_w,screen_h=self.winfo_screenwidth(),self.winfo_screenheight()
        self.geometry(f"{min(screen_w-80,max(1190,int(screen_w*.85)))}x{min(screen_h-100,max(850,int(screen_h*.85)))}")
        self.minsize(min(1020,screen_w-80),min(720,screen_h-100))
        self.admin = AdminSession()
        self.admin_busy = False
        self.stopping = False
        self.stop_pending = None
        self.cleanup_pending = None
        self.poll_inflight = False
        self.proc = None
        self.selected_target = None
        self.capture_prefix = None
        self.refresh_after = None
        self.pending_focused = False
        self.pending_scan_recovery = False
        self.pending_network_return = False
        self.scan_started_at = None
        self.empty_notice = False
        self.observed_clients=[]
        self.client_var=tk.StringVar()
        self.deauth_scope=tk.StringVar(value="client")
        self.deauth_dialog=None
        self.deauth_inflight=False
        self.deauth_cooldown_until=0
        self.deauth_count=tk.IntVar(value=1)
        self.deauth_reason=tk.StringVar(value="7 · Class 3 frame from unauthenticated station")
        self.deauth_status=tk.StringVar(value="Start a focused capture to see associated clients.")
        self.capture_focused = False
        self.closing = False
        self.emergency_active = False
        self.emergency_seen = 0
        self.restoring_wifi = False
        self._style()
        self.capture_feedback=CaptureFeedback(self)
        self.client_suitability=ClientSuitability(self)
        self.live_advisor=LiveAdvisor(self)
        self.status_dock=StatusDock(self)
        self.status_dock.pack(side='bottom',fill='x')
        self._build_navigation()
        self._build()
        self.refresh_interfaces()
        self.guided=GuidedView(self)
        self.guided.show()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.bind_all('<Control-Shift-Escape>',lambda _e:self.stop_all_now(),add='+')

    def _style(self):
        s = ttk.Style(self)
        try: s.theme_use("clam")
        except tk.TclError: pass
        # Treeview defaults use fixed pixels, which clip scaled desktop fonts.
        table_font = tkfont.nametofont("TkDefaultFont")
        row_padding = round(float(self.tk.call("tk", "scaling")) * 8)
        s.configure("Treeview", font=table_font,
                    rowheight=table_font.metrics("linespace") + row_padding)
        s.configure("Treeview.Heading", padding=(8, 6))
        self.option_add("*Dialog.msg.wrapLength", "650")
        s.configure("TFrame", background="#f4f3ff")
        s.configure("Card.TFrame", background="white")
        s.configure("TLabel", background="#f4f6f8", foreground="#182230", font=("TkDefaultFont", 10))
        s.configure("Title.TLabel", font=("TkDefaultFont", 20, "bold"), foreground="#25305a")
        s.configure("Sub.TLabel", foreground="#667085")
        s.configure("Card.TLabel", background="white")
        s.configure("CardHead.TLabel", background="white", font=("TkDefaultFont", 11, "bold"))
        s.configure("Accent.TButton", font=("TkDefaultFont", 10, "bold"))
        s.configure("Step.TLabel",background="#eef2f6",foreground="#667085",padding=(9,7),font=("TkDefaultFont",9,"bold"))
        s.configure("StepActive.TLabel",background="#e8f1ff",foreground="#175cd3",padding=(9,7),font=("TkDefaultFont",9,"bold"))
        s.configure("StepDone.TLabel",background="#eaf7ef",foreground="#067647",padding=(9,7),font=("TkDefaultFont",9,"bold"))
        s.configure("Nav.TButton",padding=(12,8),font=("TkDefaultFont",10))
        s.configure("NavActive.TButton",padding=(12,8),font=("TkDefaultFont",10,"bold"),foreground="#5648cf",background="#e8e4ff")

    def _build_navigation(self):
        bar=ttk.Frame(self,style="Card.TFrame",padding=(14,8))
        bar.pack(side="top",fill="x")
        self.nav_buttons={}
        for name,icon in (("Networks","⌁"),("Capture","◉"),("Evidence","◫"),("Recovery","◇"),("Adapters","▣"),("Activity","≡")):
            button=ttk.Button(bar,text=f"{icon}  {name}",style="Nav.TButton",command=lambda n=name:self.navigate(n))
            button.pack(side="left",padx=(0,5))
            self.nav_buttons[name]=button
        ttk.Button(bar,text="↻ Restore Wi-Fi",command=self.restore_wifi).pack(side="right")
        self._active_tab="Networks"
        self.nav_buttons["Networks"].configure(style="NavActive.TButton")

    def navigate(self,name):
        if name in ("Networks","Capture","Recovery"):
            self.guided.show()
            self.guided.set_section({"Networks":"network","Capture":"capture","Recovery":"recovery"}[name])
        else:
            self.guided.show_advanced()
            if name=="Evidence":self.main_tabs.select(self.coach_panel)
            elif name=="Adapters":self.main_tabs.select(0)
            else:
                self.main_tabs.select(self.scan_tab)
                self.notes.select(1)
        self._active_tab=name
        for label,button in self.nav_buttons.items():
            button.configure(style="NavActive.TButton" if label==name else "Nav.TButton")

    def _build(self):
        root = ttk.Frame(self, padding=12); root.pack(fill="both", expand=True)
        self.advanced_root=root
        ttk.Button(root,text="← Networks",command=lambda:self.navigate("Networks")).pack(anchor="e")
        ttk.Label(root, text="AirWatch", style="Title.TLabel").pack(anchor="w")
        ttk.Label(root, text="Explore your Wi-Fi capture", style="Sub.TLabel").pack(anchor="w", pady=(3,8))

        self.workflow = ttk.Frame(root, style="Card.TFrame", padding=14)
        # The top tabs carry navigation; keep step state for the focused action.
        ttk.Label(self.workflow, text="Guided workflow", style="CardHead.TLabel").pack(anchor="w")
        steps = ttk.Frame(self.workflow, style="Card.TFrame"); steps.pack(fill="x", pady=(10,0))
        self.step_labels=[]
        for index,title in enumerate(("1  Adapter","2  Monitor","3  Scan + select","4  Capture","5  Analyze","6  Recover")):
            label=ttk.Label(steps,text=title,style="Step.TLabel",anchor="center")
            label.pack(side="left",fill="x",expand=True,padx=(0 if index==0 else 4,0))
            self.step_labels.append(label)
        self.next_btn = ttk.Button(steps, text="Next: capture selected AP", command=self.go_next, state="disabled")
        self.next_btn.pack(side="right",padx=(8,0))
        self.target_note = ttk.Label(self.workflow, text="Choose an adapter, enable monitor mode, then start the passive scan.", style="Sub.TLabel")
        self.target_note.pack(anchor="w", pady=(8,0))

        self.main_tabs=ttk.Notebook(root);self.main_tabs.pack(fill="both",expand=True,pady=(12,0))
        setup_shell=ttk.Frame(self.main_tabs)
        self.main_tabs.add(setup_shell,text="1  Choose adapter")
        setup_canvas=tk.Canvas(setup_shell,highlightthickness=0,background="#f4f6f8")
        setup_scroll=ttk.Scrollbar(setup_shell,orient="vertical",command=setup_canvas.yview)
        setup_canvas.configure(yscrollcommand=setup_scroll.set)
        setup_scroll.pack(side="right",fill="y");setup_canvas.pack(fill="both",expand=True)
        setup_tab=ttk.Frame(setup_canvas,padding=14)
        setup_window=setup_canvas.create_window((0,0),window=setup_tab,anchor="nw")
        setup_tab.bind("<Configure>",lambda _e:setup_canvas.configure(scrollregion=setup_canvas.bbox("all")))
        setup_canvas.bind("<Configure>",lambda e:setup_canvas.itemconfigure(setup_window,width=e.width))
        row = ttk.Frame(setup_tab); row.pack(fill="x")
        self.scan_band=tk.StringVar(value="2.4 + 5 GHz")
        self.interface = tk.StringVar()
        self.interfaces = {}
        self.refreshing_targets=False
        card = ttk.Frame(row, style="Card.TFrame", padding=15); card.pack(side="left", fill="x", expand=True)
        ttk.Label(card, text="WIRELESS ADAPTERS", style="CardHead.TLabel").pack(anchor="w")
        adapter_list=ttk.Frame(card,style="Card.TFrame");adapter_list.pack(fill="x",pady=(8,6))
        self.adapter_table=ttk.Treeview(adapter_list,columns=("interface","phy","mode","channel","network"),show="headings",height=4,selectmode="browse")
        for key,label,width in (("interface","Interface",90),("phy","Radio",60),("mode","Mode",85),("channel","Channel",60),("network","Connected network",150)):
            self.adapter_table.heading(key,text=label);self.adapter_table.column(key,width=width,anchor="w")
        adapter_scroll=ttk.Scrollbar(adapter_list,orient="vertical",command=self.adapter_table.yview)
        self.adapter_table.configure(yscrollcommand=adapter_scroll.set)
        self.adapter_table.pack(side="left",fill="x",expand=True)
        adapter_scroll.pack(side="right",fill="y")
        self.adapter_table.bind("<<TreeviewSelect>>",self.select_interface)
        control=ttk.Frame(card,style="Card.TFrame");control.pack(fill="x")
        ttk.Button(control,text="↻ Refresh",command=self.refresh_interfaces).pack(side="left")
        ttk.Button(control,text="Check interference",command=self.check_blockers).pack(side="left",padx=(8,0))
        self.monitor_btn=ttk.Button(control,text="Enable monitor mode",command=self.enable_monitor)
        self.monitor_btn.pack(side="left",padx=(8,0))
        self.managed_btn=ttk.Button(control,text="Return to managed",command=self.return_managed,state="disabled")
        self.managed_btn.pack(side="left",padx=(8,0))
        network_controls=ttk.Frame(card,style="Card.TFrame")
        network_controls.pack(fill="x",pady=(8,0))
        ttk.Button(network_controls,text="Authorize session",command=self.authorize_session).pack(side="left",padx=(0,8))
        ttk.Button(network_controls,text="↻ Restore Wi-Fi",command=self.restore_wifi).pack(side="left")
        ttk.Label(network_controls,text="Stops capture and reconnects Wi-Fi",style="Card.TLabel").pack(side="left",padx=10)
        self.auth_status=ttk.Label(card,text="Administrator session locked · authorize once for this app session",style="Sub.TLabel")
        self.auth_status.pack(anchor="w",pady=(6,0))
        ttk.Button(card,text="Adapter diagnostics",command=self.adapter_diagnostics).pack(anchor="w",pady=(6,0))
        self.iface_info=ttk.Label(card,text="Looking for wireless adapters…",style="Sub.TLabel");self.iface_info.pack(anchor="w",pady=(7,0))

        card2 = ttk.Frame(row, style="Card.TFrame", padding=15); card2.pack(side="left", fill="both", padx=(12,0))
        ttk.Label(card2, text="CAPTURE", style="CardHead.TLabel").pack(anchor="w")
        self.state = ttk.Label(card2, text="●  Idle", style="Card.TLabel", foreground="#667085"); self.state.pack(anchor="w", pady=(10,6))
        self.start_btn = ttk.Button(card2, text="Start passive scan", style="Accent.TButton", command=self.start_capture); self.start_btn.pack(fill="x")
        self.stop_btn = ttk.Button(card2, text="Stop capture", command=self.stop_capture, state="disabled"); self.stop_btn.pack(fill="x", pady=(7,0))

        cap = ttk.Frame(setup_tab, style="Card.TFrame", padding=15); cap.pack(fill="x", pady=14)
        ttk.Label(cap, text="SAVE CAPTURE", style="CardHead.TLabel").pack(anchor="w")
        frow = ttk.Frame(cap, style="Card.TFrame"); frow.pack(fill="x", pady=(10,0))
        self.outdir = tk.StringVar(value=str(Path.home() / "AirWatch Captures"))
        ttk.Entry(frow, textvariable=self.outdir).pack(side="left", fill="x", expand=True)
        ttk.Button(frow, text="Choose folder…", command=self.choose_folder).pack(side="left", padx=(8,0))
        ttk.Button(frow, text="Open folder", command=self.open_folder).pack(side="left", padx=(8,0))
        ttk.Label(cap, text="Creates .cap and .csv files. Limits: 30 minutes, 512 MiB per file; stops early on low disk space or a stalled capture.", style="Sub.TLabel").pack(anchor="w", pady=(8,0))
        setup_help=ttk.Frame(setup_tab,style="Card.TFrame",padding=15);setup_help.pack(fill="x")
        ttk.Label(setup_help,text="Choosing the right adapter",style="CardHead.TLabel").pack(anchor="w")
        self.adapter_tip=ttk.Label(setup_help,text="Select an adapter above. An idle second adapter can leave your normal Wi-Fi connection available.",style="Card.TLabel",wraplength=1000,justify="left")
        self.adapter_tip.pack(anchor="w",pady=(7,0))
        ttk.Label(setup_help,text="Managed mode connects to Wi-Fi. Monitor mode listens to nearby wireless frames. AirWatch returns the selected monitor interface to managed mode when you press Return to managed.",style="Card.TLabel",wraplength=1000,justify="left").pack(anchor="w",pady=(8,0))

        self.scan_tab=ttk.Frame(self.main_tabs)
        self.main_tabs.add(self.scan_tab,text="2  Scan & capture")
        self.scan_canvas=tk.Canvas(self.scan_tab,highlightthickness=0,background='#f4f6f8')
        scan_scroll=ttk.Scrollbar(self.scan_tab,orient='vertical',command=self.scan_canvas.yview)
        self.scan_canvas.configure(yscrollcommand=scan_scroll.set)
        scan_scroll.pack(side='right',fill='y');self.scan_canvas.pack(fill='both',expand=True)
        capture_tab=ttk.Frame(self.scan_canvas,padding=14)
        scan_window=self.scan_canvas.create_window((0,0),window=capture_tab,anchor='nw')
        capture_tab.bind('<Configure>',lambda _e:self.scan_canvas.configure(scrollregion=self.scan_canvas.bbox('all')))
        self.scan_canvas.bind('<Configure>',lambda e:self.scan_canvas.itemconfigure(scan_window,width=e.width))
        def scan_wheel(event):
            if isinstance(event.widget,(tk.Text,ttk.Treeview,ttk.Combobox,ttk.Spinbox)):return
            widget=event.widget
            while widget:
                if widget is capture_tab:
                    amount=-3 if getattr(event,'num',None)==4 or getattr(event,'delta',0)>0 else 3
                    self.scan_canvas.yview_scroll(amount,'units');return 'break'
                widget=getattr(widget,'master',None)
        for event in ('<MouseWheel>','<Button-4>','<Button-5>'):self.bind_all(event,scan_wheel,add='+')
        scanbar=ttk.Frame(capture_tab,style="Card.TFrame",padding=12);scanbar.pack(fill="x",pady=(0,12))
        self.capture_heading=ttk.Label(scanbar,text="Network scan",style="CardHead.TLabel")
        self.capture_heading.pack(side="left",padx=(0,15))
        self.scan_state=ttk.Label(scanbar,text="Choose an adapter in Setup",style="Card.TLabel")
        self.scan_state.pack(side="left",fill="x",expand=True)
        ttk.Combobox(scanbar,textvariable=self.scan_band,values=("2.4 + 5 GHz","2.4 GHz","5 GHz"),state="readonly",width=16).pack(side="right",padx=10)
        self.scan_start_btn=ttk.Button(scanbar,text="Start passive scan",command=self.start_capture)
        self.scan_start_btn.pack(side="right")
        self.scan_stop_btn=ttk.Button(scanbar,text="Stop capture",command=self.stop_capture,state="disabled")
        self.scan_stop_btn.pack(side="right",padx=(0,8))
        self.capture_feedback.build(capture_tab).pack(fill="x",pady=(0,10))
        self.reconnect_panel=ReconnectPanel(capture_tab,self)
        self.reconnect_panel.pack(fill="x",pady=(0,10))
        self.client_combo=self.reconnect_panel.clients
        self.deauth_btn=self.reconnect_panel.send
        body = ttk.Frame(capture_tab); body.pack(fill="both", expand=True)
        left = ttk.Frame(body, style="Card.TFrame", padding=14); left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="Nearby access points", style="CardHead.TLabel").pack(anchor="w")
        ttk.Label(left, text="Passive beacon observations from the active capture", style="Sub.TLabel").pack(anchor="w", pady=(3,9))
        cols=("bssid","channel","security","power","essid")
        self.table=ttk.Treeview(left, columns=cols, show="headings", height=10)
        for c,label,width in zip(cols,("BSSID","CH","WPA2-Personal","Signal","Network name"),(150,48,118,65,210)):
            self.table.heading(c,text=label); self.table.column(c,width=width,anchor="w")
        self.table.pack(fill="both",expand=True)
        self.table.bind("<<TreeviewSelect>>", self.select_target)
        self.table.bind("<Double-1>", lambda _e: self.go_next() if not (self.proc and self.capture_focused) else None)
        right=ttk.Frame(body, style="Card.TFrame", padding=14); right.pack(side="left", fill="both", padx=(12,0))
        self.notes=ttk.Notebook(right); self.notes.pack(fill="both",expand=True)
        learn_tab=ttk.Frame(self.notes,style="Card.TFrame",padding=8); self.notes.add(learn_tab,text="Learn")
        self.learn=tk.Text(learn_tab,width=34,height=14,wrap="word",relief="flat",bg="#f8fafc",fg="#344054",font=("TkDefaultFont",10),padx=10,pady=10)
        self.learn.pack(fill="both",expand=True)
        self.learn.insert("end", "HOW THE WORKFLOW WORKS\n\n1 · Choose adapter and enable monitor mode\nThe adapter list shows every wireless interface and its current mode. Managed mode is used for normal Wi-Fi. Monitor mode lets the adapter listen for nearby Wi-Fi frames; enabling it may pause normal Wi-Fi on that adapter.\n\n2 · Scan\nAirodump-ng listens for broadcasts on the selected monitor interface. It does not join a network. If no access points appear, verify MONITOR mode, wait several seconds, check adapter/radio support, and try the other listed adapter.\n\n3 · Select\nChoose an access point you are authorized to assess. One row represents one wireless network radio.\n\n4 · Focused capture\nAirWatch listens on that radio’s channel and saves packets it hears. Reception depends on adapter, distance, channel, and permissions.\n\n5 · Analyze\nAfter stopping a focused capture, AirWatch checks for EAPOL or PMKID records matching the selected access point. You can return the adapter to managed mode.\n\n6 · Recover\nChoose rockyou, a custom wordlist, or a narrow mask. Estimate the work, then watch Hashcat speed, progress, and ETA.\n\nFIELD GUIDE\nBSSID · the radio’s MAC address; often, but not always, one per access point.\nChannel · the part of the Wi-Fi band the radio uses.\nSecurity · advertised encryption/authentication mode, not proof that a network is secure.\nSignal · received signal level in dBm; closer to zero is usually stronger.\nNetwork name · advertised SSID; “<hidden>” means no name was broadcast.\n\nSelect a row to see its details and a short explanation here.")
        self.learn.configure(state="disabled")
        activity_tab=ttk.Frame(self.notes,style="Card.TFrame",padding=8); self.notes.add(activity_tab,text="Activity")
        self.log=tk.Text(activity_tab,width=34,height=14,wrap="word",relief="flat",bg="#f8fafc",fg="#344054",font=("TkFixedFont",9),state="disabled")
        self.log.pack(fill="both",expand=True)
        self.coach_panel=CoachPanel(self.main_tabs,self)
        self.main_tabs.add(self.coach_panel,text="3  Evidence & AI coach")
        self.recovery_panel=RecoveryPanel(self.main_tabs,self)
        self.main_tabs.add(self.recovery_panel,text="4  Analyze & recover")
        footer=ttk.Frame(root); footer.pack(fill="x",pady=(12,0))
        ttk.Label(footer,text="Capture with airodump-ng · Analyze and recover locally with Hashcat",style="Sub.TLabel").pack(side="left")
        ttk.Label(footer,text=f"Tool: {Airodump}",style="Sub.TLabel").pack(side="right")
        self._log("Ready. Select a wireless interface to begin.")

    def update_workflow(self, stage=None, note=None):
        if stage is None:
            name=self.interface.get()
            mode=self.interfaces.get(name,{}).get("mode")
            if self.capture_focused and self.proc: stage=3
            elif hasattr(self,"recovery_panel") and self.recovery_panel.ready_hash and not self.proc: stage=5
            elif self.capture_focused and not self.proc and self.capture_prefix: stage=4
            elif self.selected_target: stage=3
            elif self.proc or mode=="monitor": stage=2
            elif name: stage=1
            else: stage=0
        for i,label in enumerate(self.step_labels):
            label.configure(style="StepDone.TLabel" if i<stage else "StepActive.TLabel" if i==stage else "Step.TLabel")
        if note:
            self.target_note.configure(text=note)
        self.sync_workflow_action()

    def sync_workflow_action(self):
        """The workflow button reflects capture state, never table refresh events."""
        if self.stopping or self.pending_focused:
            text,state="Switching capture…" if self.pending_focused else "Stopping…","disabled"
        elif self.proc and self.capture_focused:
            text,state="Stop & analyze","normal"
        elif self.proc:
            if self.selected_target and self.client_suitability.complete_record_observed():
                text,state="Stop & check WPA2 capture","normal"
            else:
                text,state=("Next: focused capture","normal") if self.client_suitability.can_capture() else ("Choose a WPA2 network","disabled")
        elif hasattr(self,"recovery_panel") and self.recovery_panel.ready_hash:
            text,state="Next: recovery","normal"
        elif self.capture_focused and self.capture_prefix:
            text,state="Next: analyze capture","normal"
        else:
            text,state=("Next: focused capture","normal") if self.selected_target else ("Select an access point","disabled")
        if self.selected_target and not self.proc and not self.recovery_panel.ready_hash and not (self.capture_focused and self.capture_prefix) and not self.client_suitability.can_capture():
            text,state="Choose a WPA2 network","disabled"
        self.next_btn.configure(text=text,state=state)
        if hasattr(self,"reconnect_panel"):
            self.reconnect_panel.refresh()

    def send_deauth(self):
        if self.admin_busy or self.stopping or not self.proc or not self.capture_focused or self.deauth_dialog is not None:return
        if time.monotonic()<self.deauth_cooldown_until:return
        scope=self.deauth_scope.get()
        if scope not in ("client","network"):return
        client=self.client_var.get().strip().lower()
        if scope=="client" and client not in self.observed_clients:
            self.deauth_status.set("Choose a device observed in this capture, or choose Whole selected network.");return
        if scope=="client" and client in self.client_suitability.unsuitable_clients():
            self.deauth_status.set("This device is not suitable for the WPA2 recovery test. Choose a WPA2-Personal client instead.");return
        try:count=int(self.deauth_count.get());reason=int(self.deauth_reason.get().split()[0])
        except (ValueError,tk.TclError):messagebox.showerror(APP,"Choose a burst count from 1 to 5.");return
        if not 1<=count<=5 or reason not in (1,3,7):
            messagebox.showerror(APP,"Choose 1 to 5 bursts and a listed reason.");return
        target=dict(self.selected_target);prefix=self.capture_prefix
        whole=scope=="network"
        dialog=tk.Toplevel(self);self.deauth_dialog=dialog
        dialog.title("Reconnect whole network?" if whole else "Reconnect this device?")
        dialog.transient(self);dialog.resizable(False,False)
        panel=ttk.Frame(dialog,padding=24);panel.pack(fill="both",expand=True)
        ttk.Label(panel,text=dialog.title(),font=("TkDefaultFont",17,"bold")).pack(anchor="w",pady=(0,12))
        impact=("This may briefly disconnect every device on this access point, including this computer if it is connected. It affects this selected radio, not other access points sharing the network name."
                if whole else "This may briefly disconnect the selected device so it reconnects. Other devices are not targeted.")
        ttk.Label(panel,text=impact,wraplength=620,justify="left").pack(fill="x")
        details=f"Network: {target['essid']}\nAccess point: {target['bssid']} · channel {target['channel']}\nScope: {'All devices on this access point' if whole else client}\nBursts: {count} · reason: {reason}"
        ttk.Label(panel,text=details,wraplength=620,justify="left").pack(anchor="w",pady=16)
        ttk.Label(panel,text="Capture continues. This is one bounded command, not a repeating attack. Protected management frames may prevent disconnection; sending it does not confirm a handshake.",wraplength=620,justify="left").pack(fill="x")
        buttons=ttk.Frame(panel);buttons.pack(fill="x",pady=(18,0))
        def cancel():
            if self.deauth_dialog is dialog:self.deauth_dialog=None
            dialog.destroy()
        def confirm():
            cancel()
            current=self.selected_target or {}
            if self.admin_busy or self.stopping or self.closing or not self.proc or self.capture_prefix!=prefix or any(current.get(key)!=target.get(key) for key in ('bssid','channel')):
                self.deauth_status.set("Capture changed. Review the current network and try again.");return
            self._send_reconnect(scope,client,count,reason,target['bssid'],prefix)
        ttk.Button(buttons,text="Cancel",command=cancel).pack(side="left")
        self.deauth_confirm_btn=ttk.Button(buttons,text="Send whole-network burst" if whole else "Send device burst",command=confirm,style="Accent.TButton")
        self.deauth_confirm_btn.pack(side="right")
        dialog.protocol("WM_DELETE_WINDOW",cancel);dialog.bind("<Escape>",lambda _e:cancel())
        dialog.update_idletasks();dialog.geometry(f"+{max(0,self.winfo_rootx()+80)}+{max(0,self.winfo_rooty()+100)}");dialog.lift()
        self.sync_workflow_action()

    def _send_reconnect(self,scope,client,count,reason,bssid,prefix):
        # No nested Tk wait or global button disabling while the short command runs.
        self.admin_busy=True;self.deauth_inflight=True
        self.deauth_cooldown_until=time.monotonic()+15
        self.deauth_status.set("Sending reconnect burst; capture continues…")
        results=queue.Queue()
        def worker():
            try:results.put((True,self.admin.request("deauth",scope=scope,client=client if scope=="client" else "",count=count,reason=reason,bssid=bssid,capture_prefix=prefix)))
            except Exception as exc:results.put((False,str(exc)))
        threading.Thread(target=worker,daemon=True).start()
        def receive():
            try:ok,result=results.get_nowait()
            except queue.Empty:self.after(80,receive);return
            self.admin_busy=False;self.deauth_inflight=False
            if ok:
                output=(result.get("stdout","")+result.get("stderr","")).strip()
                self._log(f"Reconnect test ({scope}):\n"+output)
                self.deauth_status.set("Burst finished. Capture continues; watch Handshake status for the result." if result['returncode']==0 else "Burst failed or timed out. Review Activity for details; capture is still running.")
            else:
                self.deauth_status.set(result);self._log("Reconnect test: "+result)
            self.sync_workflow_action()
        self.after(80,receive)

    def details_dialog(self, title, explanation, details, action=None, cancel="Close"):
        dialog=tk.Toplevel(self)
        dialog.title(title)
        dialog.transient(self)
        width=min(1000,self.winfo_screenwidth()-100)
        height=min(650,self.winfo_screenheight()-150)
        dialog.geometry(f"{width}x{height}")
        dialog.minsize(min(650,width),min(400,height))
        panel=ttk.Frame(dialog,padding=20);panel.pack(fill="both",expand=True)
        label=ttk.Label(panel,text=explanation,justify="left",wraplength=width-60)
        label.pack(fill="x",pady=(0,15))
        label.bind("<Configure>",lambda event:label.configure(wraplength=max(200,event.width)))
        body=ttk.Frame(panel);body.pack(fill="both",expand=True)
        text=tk.Text(body,wrap="word",font="TkFixedFont",height=10,padx=12,pady=12)
        scroll=ttk.Scrollbar(body,command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right",fill="y");text.pack(fill="both",expand=True)
        text.insert("1.0",details);text.configure(state="disabled")
        buttons=ttk.Frame(panel);buttons.pack(fill="x",pady=(15,0))
        accepted=False
        def finish(value):
            nonlocal accepted
            accepted=value
            dialog.destroy()
        def emergency():
            finish(False)
            self.after_idle(self.stop_all_now)
        ttk.Button(buttons,text='■ Stop all now',style='Emergency.TButton',command=emergency).pack(side='left')
        ttk.Button(buttons,text=cancel,command=lambda:finish(False)).pack(side="right")
        if action:
            ttk.Button(buttons,text=action,style="Accent.TButton",command=lambda:finish(True)).pack(side="right",padx=10)
        dialog.protocol("WM_DELETE_WINDOW",lambda:finish(False))
        dialog.bind("<Escape>",lambda event:finish(False))
        dialog.grab_set();self.wait_window(dialog)
        return accepted

    def check_blockers(self, for_monitor=False):
        if self.proc:
            messagebox.showinfo(APP,"Stop the capture before changing network services.");return False
        if not os.path.isfile(Airmon):
            messagebox.showerror(APP,"airmon-ng was not found. Install Aircrack-ng first.");return False
        try:
            result=self._run_privileged([Airmon,"check"],timeout=120)
        except Exception as e:
            messagebox.showerror(APP,f"Could not check for interference:\n{e}");return False
        output=(result.stdout+result.stderr).strip() or "No interfering processes were reported."
        self._log("airmon-ng check:\n"+output)
        if result.returncode:
            self.details_dialog("Interference check failed","The check did not complete. Review the details below.",output)
            return False
        blockers=re.findall(r"^\s*(\d+)\s+(\S+)",output,re.MULTILINE)
        if not blockers:
            if not for_monitor:self.details_dialog("Interference check","No interfering processes found.",output)
            return True
        accepted=self.details_dialog("Stop interfering processes?",
            "These processes can change channels or return the adapter to managed mode. "
            "Stop them now? This runs airmon-ng check kill and can disconnect networking on ALL adapters, "
            "including your current internet connection. Use Restore networking afterward.",
            output,action="Stop interfering processes",cancel="Cancel" if for_monitor else "Leave running")
        if not accepted:return False
        try:
            result=self._run_privileged([Airmon,"check","kill"],timeout=120)
            output=(result.stdout+result.stderr).strip()
            self._log("airmon-ng check kill:\n"+output)
            if result.returncode:
                self.details_dialog("Could not stop interference","The command reported a problem. Restore networking is available below the adapter controls.",output)
                return False
            check=self._run_privileged([Airmon,"check"],timeout=120)
            remaining=(check.stdout+check.stderr).strip()
            if check.returncode or re.search(r"^\s*\d+\s+\S+",remaining,re.MULTILINE):
                self.details_dialog("Interference remains","Some processes may have restarted. Review these details before continuing.",remaining)
                return False
            self.refresh_interfaces()
            if not for_monitor:self.details_dialog("Interference cleared","Interfering processes were stopped. You can now enable monitor mode. Use Restore networking when finished.",output or "Command completed successfully.")
            return True
        except Exception as e:
            messagebox.showerror(APP,f"Could not finish stopping interference:\n{e}\n\nUse Restore networking if your connection was interrupted.")
            return False

    def restore_networking(self):
        if self.proc:
            messagebox.showinfo(APP,"Stop the capture before restoring networking.");return
        accepted=self.details_dialog("Restore networking?",
            "Restart NetworkManager and wpa_supplicant to restore normal Wi-Fi connections. "
            "Return your capture adapter to managed mode first. Restarting services may briefly interrupt current connections.",
            "AirWatch will request system authorization and run:\nsystemctl restart NetworkManager.service wpa_supplicant.service",
            action="Restore networking",cancel="Cancel")
        if not accepted:return
        try:
            systemctl=shutil.which("systemctl")
            if not systemctl:raise RuntimeError("systemctl is not installed on this system.")
            result=self._run_privileged([systemctl,"restart","NetworkManager.service","wpa_supplicant.service"],timeout=120)
            output=(result.stdout+result.stderr).strip()
            self._log("Restore networking: "+(output or f"exit code {result.returncode}"))
            self.details_dialog("Restore networking", "Networking services restarted. Connections may take a few seconds to return." if result.returncode==0 else "Networking could not be fully restored. Review the details below.",output or "Command completed successfully.")
            self.refresh_interfaces()
        except Exception as e:
            messagebox.showerror(APP,f"Could not restore networking:\n{e}")

    def restore_wifi(self):
        """One action for stopping capture and returning the laptop to Wi-Fi."""
        if self.restoring_wifi:return
        self.restoring_wifi=True
        self.restore_started_at=time.monotonic()
        self.pending_focused=False
        self.pending_scan_recovery=False
        self.pending_network_return=False
        self._log('Restoring Wi-Fi: stopping capture and resetting the adapter.')
        self._restore_wifi_step()

    def _restore_wifi_step(self):
        if time.monotonic()-self.restore_started_at>45:
            self.restoring_wifi=False
            self._log('Wi-Fi restoration timed out while stopping the capture.')
            messagebox.showerror(APP,'Capture did not stop. Use ■ Stop all, then try Restore Wi-Fi again.')
            return
        if self.proc:
            if not self.stopping:self.stop_capture()
            self.after(150,self._restore_wifi_step)
            return
        if self.admin_busy:
            self.after(150,self._restore_wifi_step)
            return
        try:
            name=self.interface.get() or None
            result=self._wait_task(lambda:self.admin.request('restore_wifi',interface=name))
            self.refresh_interfaces()
            if result.get('connected'):
                self._log('Wi-Fi restored and connected.')
                messagebox.showinfo(APP,'Wi-Fi restored and connected.')
            else:
                self._log('Wi-Fi is enabled; waiting for a saved network to connect.')
                messagebox.showinfo(APP,'Wi-Fi is enabled. Select your network in the system Wi-Fi menu if it does not reconnect automatically.')
        except Exception as exc:
            self._log('Wi-Fi restoration needs attention: '+str(exc))
            messagebox.showerror(APP,'Wi-Fi restoration needs attention:\n'+str(exc))
        finally:
            self.restoring_wifi=False

    def open_folder(self):
        folder=Path(self.outdir.get()).expanduser()
        try:
            folder.mkdir(parents=True,exist_ok=True)
            subprocess.Popen(["xdg-open",str(folder)])
        except (OSError,subprocess.SubprocessError) as e:
            messagebox.showerror(APP,f"Could not open the capture folder:\n{e}")

    def _log(self,msg):
        if hasattr(self,'status_dock'):
            self.status_dock.append_activity(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log.configure(state="normal")
        self.log.insert("end",f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        if int(self.log.index("end-1c").split(".")[0])>1200:
            self.log.delete("1.0","end-1200l")
        self.log.see("end");self.log.configure(state="disabled")

    def _wait_task(self, function):
        """Keep Tk painting while authorization/commands run on a worker."""
        if threading.current_thread() is not threading.main_thread():return function()
        if self.admin_busy:raise RuntimeError("An administrative operation is already in progress.")
        self.admin_busy=True
        done=tk.BooleanVar(self,value=False);results=queue.Queue()
        buttons=[]
        def disable(parent):
            for widget in parent.winfo_children():
                if isinstance(widget,ttk.Button):
                    if widget is self.status_dock.emergency_button:continue
                    buttons.append((widget,widget.state()))
                    widget.state(["disabled"])
                disable(widget)
        disable(self)
        self.auth_status.configure(text="Working… complete the system authorization prompt if shown")
        def worker():
            try:results.put((True,function()))
            except Exception as e:results.put((False,e))
        threading.Thread(target=worker,daemon=True).start()
        def check():
            if results.empty():self.after(80,check)
            else:done.set(True)
        self.after(80,check)
        self.wait_variable(done)
        ok,value=results.get()
        self.admin_busy=False
        for widget,state in buttons:
            if widget.winfo_exists():widget.state(["!disabled"]);widget.state(state)
        self.auth_status.configure(text="Administrator session active · password is never stored" if self.admin.process and self.admin.process.poll() is None else "Administrator session locked")
        if not ok:raise value
        return value

    def _cancel_local_work(self):
        self.emergency_active=True
        self.pending_focused=False
        self.capture_feedback.dismiss()
        self.live_advisor.cancel()
        if self.deauth_dialog:
            self.deauth_dialog.destroy();self.deauth_dialog=None
        self.recovery_panel.cancel_requested=True
        self.recovery_panel.stop_attack()
        runner=self.coach_panel.runner
        if runner:
            runner.stopped.set()
            threading.Thread(target=runner.stop,daemon=True).start()
        self.coach_panel.status.set('Emergency stop requested. Analysis cancelled.')
        self.guided.notice='Emergency stop requested. Running work is being interrupted.'

    def observe_emergency_marker(self):
        directory=getattr(self.admin,'control_dir',None)
        if directory is None:return
        try:stamp=int((directory/'stop').read_text())
        except (OSError,ValueError):return
        if stamp>self.emergency_seen:
            self.emergency_seen=stamp
            self._cancel_local_work()

    def stop_all_now(self):
        self._cancel_local_work()
        self._log('EMERGENCY STOP requested. Interrupting owned capture, reconnect, analysis and recovery workers.')
        results=queue.Queue()
        def worker():
            try:results.put((True,self.admin.emergency_stop()))
            except Exception as exc:results.put((False,str(exc)))
        threading.Thread(target=worker,daemon=True).start()
        def receive():
            try:ok,result=results.get_nowait()
            except queue.Empty:self.after(60,receive);return
            if ok:
                self.emergency_seen=max(self.emergency_seen,result['requested_at'])
                errors=result.get('errors',[])
                self._log('Emergency stop sent.'+(' Some work could not be confirmed stopped: '+'; '.join(errors) if errors else ' Adapter restoration will follow.'))
                self.guided.notice='Emergency stop sent. Work has been interrupted; saved capture files remain available.'
                self.deauth_status.set('Emergency stop requested. Start a new capture when ready.')
                if self.proc:self.stop_capture()
            else:
                self._log('Emergency stop could not complete: '+result)
                self.guided.notice='Emergency stop could not complete. Use the independent Stop AirWatch Now launcher.'
        self.after(60,receive)

    def _run_privileged(self, args, timeout=25):
        return self._wait_task(lambda:self.admin.run(args))

    def authorize_session(self):
        try:self._wait_task(lambda:self.admin.request("status"))
        except Exception as e:messagebox.showerror(APP,str(e))

    def adapter_diagnostics(self):
        try:
            result=self._wait_task(lambda:subprocess.run(
                ["journalctl","-k","-b","-n","600","--no-pager"],capture_output=True,text=True,timeout=10))
            lines=[line for line in result.stdout.splitlines() if any(word in line.lower() for word in ("rtw", "iwlwifi", "wlan", "firmware"))]
            self.details_dialog("Adapter diagnostics",
                "Only adapters initialized by Linux can appear in the table. Firmware or driver initialization errors can prevent a connected USB adapter from appearing.",
                "\n".join(lines[-80:]) or result.stderr or "No wireless driver messages are available.")
        except Exception as e:messagebox.showerror(APP,str(e))

    def cleanup_network(self):
        if self.admin_busy:
            if self.cleanup_pending is None:
                def retry():
                    self.cleanup_pending=None
                    self.cleanup_network()
                self.cleanup_pending=self.after(100,retry)
            return False
        if not self.admin.process:return True
        try:
            self._wait_task(lambda:self.admin.request("cleanup"))
            self.refresh_interfaces()
            self._log("Session capture stopped; tracked monitor adapters and previously active network services restored.")
        except Exception as e:
            self._log(f"Network cleanup needs attention: {e}")
            messagebox.showerror(APP,f"Network cleanup could not complete:\n{e}\nUse Return to managed and Restore networking.")

    def _restore_after_capture(self):
        try:
            result=self._wait_task(lambda:self.admin.request('restore_wifi',interface=self.interface.get() or None))
            self.refresh_interfaces()
            self._log('Capture stopped; Wi-Fi adapter restored.'+(' Connected.' if result.get('connected') else ' Waiting for a saved network.'))
        except Exception as exc:
            self._log('Wi-Fi needs attention: '+str(exc))
            messagebox.showerror(APP,'Wi-Fi needs attention:\n'+str(exc)+'\nUse Restore Wi-Fi at the top.')

    def _read_interfaces(self):
        p=subprocess.run(["iw","dev"],capture_output=True,text=True,timeout=5)
        found={}
        current=None
        phy=""
        for line in p.stdout.splitlines():
            stripped=line.strip()
            if stripped.startswith("phy#"):
                phy=stripped
                current=None
            elif stripped.startswith("Unnamed/"):
                current=None
            elif stripped.startswith("Interface "):
                current=stripped.split(None,1)[1]
                found[current]={"name":current,"mode":"unknown","phy":phy}
            elif current and stripped.startswith("type "):
                found[current]["mode"]=stripped.split(None,1)[1].lower()
            elif current and stripped.startswith("channel "):
                match=re.match(r"channel\s+(\d+)",stripped)
                if match:found[current]["channel"]=match.group(1)
            elif current and stripped.startswith("ssid "):
                found[current]["ssid"]=stripped.split(None,1)[1]
        return found

    def refresh_interfaces(self, prefer_mode=None, prefer_phy=None):
        try:
            found=self._read_interfaces()
            self.interfaces=found
            names=list(found)
            self.adapter_table.delete(*self.adapter_table.get_children())
            for name,item in found.items():
                self.adapter_table.insert("","end",iid=name,values=(name,item.get("phy","—"),item["mode"].upper(),item.get("channel","—"),item.get("ssid","—")))
            selected=self.interface.get()
            if prefer_mode:
                preferred=[n for n,v in found.items() if v["mode"]==prefer_mode and (not prefer_phy or v["phy"]==prefer_phy)]
                if preferred:selected=preferred[0]
            if selected not in found and names:
                selected=next((n for n,v in found.items() if v.get("mode")=="managed" and not v.get("ssid")),names[0])
            if selected in found:
                self.interface.set(selected)
                self.adapter_table.selection_set(selected)
                self.adapter_table.focus(selected)
            connected=[n for n,v in found.items() if v.get("ssid")]
            idle=[n for n,v in found.items() if v.get("mode")=="managed" and not v.get("ssid")]
            if connected and idle:
                self.adapter_tip.configure(text=f"{connected[0]} is currently connected to Wi-Fi. {idle[0]} appears idle, so try {idle[0]} for monitor mode if its driver supports it.")
            elif names:
                self.adapter_tip.configure(text="Choose the adapter that supports monitor mode. Switching an adapter used for Wi-Fi may interrupt that connection.")
            else:
                self.adapter_tip.configure(text="No wireless adapters were found. Check that the adapter is connected and recognized by Linux.")
            self.update_interface_controls()
            self._log("Wireless adapters: "+(", ".join(f"{n} ({v['mode']})" for n,v in found.items()) if found else "none found"))
        except Exception as e:
            self.iface_info.configure(text=f"Could not read wireless adapters: {e}")
            self._log(f"Could not query wireless adapters: {e}")

    def select_interface(self, _event=None):
        chosen=self.adapter_table.selection()
        if not chosen:return
        new_interface=chosen[0]
        if new_interface!=self.interface.get() and (self.proc or self.recovery_panel.job_running):
            if self.interface.get() in self.adapter_table.get_children():self.adapter_table.selection_set(self.interface.get())
            return
        if new_interface!=self.interface.get():
            self.selected_target=None
            if not self.recovery_panel.job_running:self.recovery_panel.ready_hash=None
            self.next_btn.configure(state="disabled",text="Next: capture selected AP")
            self.table.delete(*self.table.get_children())
        self.interface.set(new_interface)
        self.update_interface_controls()
        self.update_workflow()

    def update_interface_controls(self):
        name=self.interface.get()
        item=self.interfaces.get(name,{})
        mode=item.get("mode","unknown")
        if mode=="monitor":
            self.iface_info.configure(text=f"Selected {name}: MONITOR mode on {item.get('phy','radio')}. Ready to scan.")
            self.monitor_btn.configure(state="disabled")
            self.managed_btn.configure(state="normal" if not self.proc else "disabled")
            self.start_btn.configure(state="normal" if not self.proc else "disabled")
            self.scan_start_btn.configure(state="normal" if not self.proc else "disabled")
            self.scan_state.configure(text=f"{name} is in MONITOR mode · ready")
        elif mode=="managed":
            self.iface_info.configure(text=f"Selected {name}: MANAGED mode. Enable monitor mode before scanning; Wi-Fi on this adapter may pause.")
            self.monitor_btn.configure(state="normal" if not self.proc else "disabled")
            self.managed_btn.configure(state="disabled")
            self.start_btn.configure(state="disabled")
            self.scan_start_btn.configure(state="disabled")
            self.scan_state.configure(text=f"{name} is in MANAGED mode · enable monitor mode in Setup")
        else:
            self.iface_info.configure(text=f"Selected {name or 'no adapter'}: mode is {mode}. Refresh the adapter list.")
            self.monitor_btn.configure(state="normal" if name else "disabled")
            self.managed_btn.configure(state="disabled")
            self.start_btn.configure(state="disabled")
            self.scan_start_btn.configure(state="disabled")
            self.scan_state.configure(text="Select a monitor-mode adapter in Setup")

    def enable_monitor(self):
        name=self.interface.get()
        item=self.interfaces.get(name)
        if not item:
            messagebox.showerror(APP,"Select a wireless interface first.");return
        if self.proc:
            messagebox.showinfo(APP,"Stop the capture before changing adapter mode.");return
        if item.get("mode")=="monitor":return
        if not os.path.isfile(Airmon):
            messagebox.showerror(APP,"airmon-ng was not found. Install Aircrack-ng and refresh.");return
        if not messagebox.askyesno("Enable monitor mode",f"Enable monitor mode for {name}?\n\nThis can interrupt normal Wi-Fi use on this adapter. AirWatch will check for interference and ask before stopping any processes."):
            return
        if not self.check_blockers(for_monitor=True):return
        phy=item.get("phy")
        try:
            result=self._run_privileged([Airmon,"start",name])
        except Exception as e:
            messagebox.showerror(APP,f"Could not enable monitor mode:\n{e}");return
        output=(result.stdout+result.stderr).strip()
        self._log("airmon-ng start output: "+(output or f"exit code {result.returncode}"))
        if result.returncode:
            messagebox.showerror(APP,(output or "airmon-ng could not enable monitor mode.")+"\n\nIf another service is controlling the adapter, check the Activity panel and your Linux wireless setup.")
            self.refresh_interfaces();return
        self.refresh_interfaces(prefer_mode="monitor",prefer_phy=phy)
        if self.interfaces.get(self.interface.get(),{}).get("mode")=="monitor":
            self.update_workflow(stage=2,note="Monitor mode is ready. Step 3: start the passive scan to discover nearby access points.")
            self._log(f"Monitor mode enabled. Selected {self.interface.get()} for scanning.")
            self.main_tabs.select(self.scan_tab)
        else:
            messagebox.showwarning(APP,"airmon-ng reported success, but iw did not show a monitor interface. Refresh the interface list and check the Activity panel.")

    def return_managed(self):
        name=self.interface.get()
        item=self.interfaces.get(name)
        if not item or item.get("mode")!="monitor":
            messagebox.showinfo(APP,"Select an interface currently shown as monitor mode.");return
        if self.proc:
            messagebox.showinfo(APP,"Stop the capture before returning to managed mode.");return
        if not messagebox.askyesno("Return to managed mode",f"Stop monitor mode on {name}?\n\nThis restores the adapter for normal Wi-Fi use where supported."):
            return
        phy=item.get("phy")
        try:
            result=self._run_privileged([Airmon,"stop",name])
        except Exception as e:
            messagebox.showerror(APP,f"Could not return to managed mode:\n{e}");return
        output=(result.stdout+result.stderr).strip()
        self._log("airmon-ng stop output: "+(output or f"exit code {result.returncode}"))
        if result.returncode:
            messagebox.showerror(APP,output or "airmon-ng could not stop monitor mode.");self.refresh_interfaces();return
        self.refresh_interfaces(prefer_mode="managed",prefer_phy=phy)
        self.update_workflow(stage=4,note="Managed mode restored. Use Restore networking to restart Wi-Fi services if you stopped interference.")
        self.restore_networking()

    def select_target(self, _event=None):
        if self.refreshing_targets:return
        chosen=self.table.selection()
        if not chosen:return
        values=self.table.item(chosen[0],"values")
        if len(values)<5:return
        if self.selected_target and self.selected_target['bssid']==values[0]:
            self.selected_target['signal']=values[3]
            self.sync_workflow_action()
            return
        if self.selected_target and self.selected_target['bssid']!=values[0]:
            if self.recovery_panel.job_running or (self.proc and self.capture_focused):
                old=self.selected_target['bssid']
                if old in self.table.get_children():self.table.selection_set(old)
                return
            self.recovery_panel.ready_hash=None
            self.recovery_panel.analysis_var.set("Target changed. Analyze a capture for this access point before recovery.")
            self.coach_panel.snapshot=None
        self.selected_target={"bssid":values[0],"channel":values[1],"security":values[2],"signal":values[3],"essid":values[4]}
        self.client_suitability.select(self.selected_target)
        t=self.selected_target
        if self.proc and self.capture_focused:
            self.update_workflow(stage=3,note=f"Focused capture running for {t['essid']} · channel {t['channel']}. Use Stop & analyze when ready.")
        else:
            self.update_workflow(stage=3,note=f"Selected: {t['essid']} · {t['bssid']} · channel {t['channel']} · {t['security']}")
        if not (self.proc and self.capture_focused):self.notes.select(0)
        self.learn.configure(state="normal")
        self.learn.delete("1.0","end")
        self.learn.insert("end", f"SELECTED ACCESS POINT\n\n{t['essid']}\n\nBSSID: {t['bssid']}\nThis identifies the radio in the capture. A router may advertise multiple BSSIDs.\n\nChannel: {t['channel']}\nA focused capture stays on this channel. If the channel is blank or unusual, the capture may need adjustment.\n\nSecurity: {t['security']}\nThis is metadata reported by the beacon. It does not reveal the password or guarantee the configuration is safe.\n\nSignal: {t['signal']} dBm\nA rough indication of how strongly your adapter hears the access point. It can change with position and interference.\n\nNEXT STEP\nReview the selected details, then choose Next: focused capture. AirWatch will listen on this BSSID and channel and save a timestamped capture. Stop it when you have enough data; AirWatch will open the analysis view.")
        if self.proc and self.capture_focused:
            self.learn.insert("end","\n\nCAPTURE IS ALREADY RUNNING\nThe radio stays on the selected channel. Use Stop & analyze to move forward. Use Reconnect devices for one device or an explicitly confirmed whole-network burst. The handshake status above tells you when evidence arrives.\n\nWPA2-PERSONAL CHECK\nAn access point can support WPA2 while a connected device uses another authentication mode. The recovery test requires a WPA2-PSK exchange from the specific client. Protected management frames may reject disconnect requests.")
        self.learn.configure(state="disabled")
        self.recovery_panel.target_var.set(f"Selected: {t['essid']}  ·  {t['bssid']}")
        self._log(f"Selected access point {t['essid']} ({t['bssid']}).")

    def go_next(self):
        if self.admin_busy or self.stopping or self.pending_focused:return
        if self.proc and self.capture_focused:
            self.stop_capture();return
        if not self.proc and (self.recovery_panel.ready_hash or (self.capture_focused and self.capture_prefix)):
            self.main_tabs.select(self.recovery_panel)
            if not self.recovery_panel.ready_hash:self.recovery_panel.on_capture_finished()
            return
        if not self.selected_target:return
        self.client_suitability.refresh()
        if self.proc and not self.capture_focused and self.client_suitability.complete_record_observed():
            self.pending_scan_recovery=True
            self.stop_capture()
            return
        if not self.client_suitability.can_capture():
            messagebox.showinfo(APP,self.client_suitability.state()[1]);return
        t=self.selected_target
        message=(f"Start focused passive capture?\n\nAccess point: {t['essid']}\nBSSID: {t['bssid']}\nChannel: {t['channel']}\n\nAirodump-ng will listen for packets on this access point and channel. This capture step does not connect or disconnect clients. Captured traffic may contain sensitive information, so use only with permission.")
        if not messagebox.askyesno("Step 4 · Focused capture",message):return
        if self.proc:
            self.pending_focused=True
            self.sync_workflow_action()
            self._log("Finishing the general scan before starting the focused capture.")
            self.stop_capture()
        else:
            self.start_capture(focused=True)

    def choose_folder(self):
        d=filedialog.askdirectory(initialdir=self.outdir.get() or str(Path.home()))
        if d: self.outdir.set(d)

    def start_capture(self, focused=False):
        if self.proc or self.admin_busy:return
        if focused:
            self.client_suitability.refresh()
            if not self.client_suitability.can_capture():
                messagebox.showinfo(APP,self.client_suitability.state()[1]);return
        self.emergency_active=False
        if self.recovery_panel.job_running:
            messagebox.showinfo(APP, "Stop the current Hashcat run before starting another capture.")
            return
        iface=self.interface.get()
        if not iface: messagebox.showerror(APP,"Select a wireless interface first."); return
        mode=self.interfaces.get(iface,{}).get("mode")
        if mode!="monitor":
            messagebox.showerror(APP,"The selected interface is not in monitor mode. Enable monitor mode, refresh the interface list, select the monitor interface, then scan."); return
        if not os.path.isfile(Airodump) or not os.access(Airodump,os.X_OK): messagebox.showerror(APP,"airodump-ng was not found. Install Aircrack-ng and refresh."); return
        folder=Path(self.outdir.get()).expanduser()
        try: folder.mkdir(parents=True,exist_ok=True)
        except OSError as e: messagebox.showerror(APP,f"Cannot create capture folder:\n{e}"); return
        if shutil.disk_usage(folder).free<1024**3:
            messagebox.showerror(APP,"Less than 1 GiB of disk space remains. Free space before capturing.");return
        self.capture_prefix=str(folder / (time.strftime("capture_%Y%m%d_%H%M%S_")+uuid.uuid4().hex[:8]))
        if not self.recovery_panel.job_running:
            self.recovery_panel.ready_hash=None
            self.recovery_panel.analysis_var.set("Waiting for the new capture.")
        if not focused:
            self.selected_target=None
            self.table.delete(*self.table.get_children())
            self.next_btn.configure(state="disabled",text="Select an AP to continue")
        self.observed_clients=[];self.client_var.set("");self.client_combo.configure(values=())
        self.deauth_scope.set("client");self.deauth_status.set("Start a focused capture to see associated devices.")
        self.capture_focused=bool(focused)
        self.scan_started_at=time.monotonic()
        self.empty_notice=False
        cmd=[Airodump,"--background","1","--update","2","--write-interval","2","--write",self.capture_prefix,"--output-format","pcap,csv"]
        if not focused:cmd.extend(["--band",{"2.4 + 5 GHz":"abg","2.4 GHz":"bg","5 GHz":"a"}[self.scan_band.get()]])
        if focused and self.selected_target:
            try: ch=int(self.selected_target["channel"])
            except (ValueError,TypeError): ch=None
            if ch and ch>0: cmd.extend(["--channel",str(ch)])
            cmd.extend(["--bssid",self.selected_target["bssid"]])
        cmd.append(iface)
        try:
            self.proc=self._wait_task(lambda:CaptureProcess(self.admin,cmd))
        except Exception as e:
            self.cleanup_network()
            messagebox.showerror(APP,f"Could not start capture:\n{e}");return
        self.state.configure(text=f"●  Capturing on {iface}",foreground="#027a48")
        self.start_btn.configure(state="disabled"); self.stop_btn.configure(state="normal")
        self.scan_start_btn.configure(state="disabled");self.scan_stop_btn.configure(state="normal")
        self.capture_heading.configure(text="Focused capture" if focused else "Network scan")
        self.scan_state.configure(text=f"Listening on {iface}"+(f" · channel {self.selected_target['channel']}" if focused else " · discovering access points"))
        self.main_tabs.select(self.scan_tab)
        self._log(f"Started {'focused' if focused else 'general'} passive capture on {iface}; files saved under {self.capture_prefix}.")
        if focused:
            self.update_workflow(stage=3,note=f"Focused capture running for {self.selected_target['essid']} on channel {self.selected_target['channel']}. Watch Handshake status below; a popup will ask whether to stop.")
            self.sync_workflow_action()
        else:
            self.update_workflow(stage=2,note="Scanning nearby access points. Select a row when you find the network you are authorized to assess.")
        self._poll()

    def _poll(self):
        self.refresh_after=None
        if not self.proc or self.stopping:return
        if self.admin_busy or self.poll_inflight:
            self.refresh_after=self.after(500,self._poll);return
        # Status requests use the session lock without a nested Tk event loop.
        # A user can stop while this request is in flight; stale results are ignored.
        process=self.proc
        self.poll_inflight=True
        result=queue.Queue()
        def worker():
            try:result.put((True,process.poll()))
            except Exception as exc:result.put((False,exc))
        threading.Thread(target=worker,daemon=True).start()
        def receive():
            try:ok,value=result.get_nowait()
            except queue.Empty:
                self.after(80,receive);return
            self.poll_inflight=False
            if self.proc is not process or self.stopping:return
            if self.admin_busy:
                self.refresh_after=self.after(500,self._poll);return
            if not ok:
                self._log(f"Capture status failed: {value}. Use Stop capture to retry cleanup.")
                self.refresh_after=self.after(2000,self._poll);return
            if value is not None:
                reason=process.reason
                self._read_csv();self._finish();self._restore_after_capture()
                tail=""
                try:
                    with Path(self.capture_prefix+".log").open("rb") as f:
                        f.seek(0,2);size=f.tell();f.seek(max(0,size-1200))
                        tail=f.read(1200).decode(errors="replace")
                except OSError:pass
                self._log(f"Capture exited (code {value}). {reason}\n{tail}")
                self.update_workflow(note=reason or "Capture ended. Review Activity and Adapter diagnostics.")
                return
            self._read_csv();self.coach_panel.maybe_live()
            if not self.table.get_children() and not self.empty_notice and self.scan_started_at and time.monotonic()-self.scan_started_at>12:
                self.empty_notice=True
                note="No access points yet. A capture receiving no packets stops automatically after 60 seconds. Use Adapter diagnostics to check firmware and driver errors."
                self.update_workflow(stage=2,note=note);self._log(note)
            self.refresh_after=self.after(2000,self._poll)
        self.after(80,receive)

    def _read_csv(self):
        if not self.capture_prefix:return
        path=Path(self.capture_prefix+"-01.csv")
        if not path.exists(): return
        try:
            rows=[];clients=[]
            if path.stat().st_size>8*1024*1024:
                self._log("CSV exceeds the display size limit; stop capture and review the file.");return
            with path.open(errors="replace") as f:
                reader=csv.reader(f); section=None
                for row in reader:
                    if not row:continue
                    if row[0].strip()=="BSSID":section="aps";continue
                    if row[0].strip()=="Station MAC":section="stations";continue
                    if section=="stations" and len(row)>=6:
                        station=row[0].strip().lower();ap=row[5].strip().lower()
                        if self.selected_target and ap==self.selected_target['bssid'].lower() and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",station) and not int(station[:2],16)&1:
                            clients.append(station)
                        continue
                    if section!="aps" or len(row)<14 or not row[0].strip(): continue
                    bssid=row[0].strip(); ch=row[3].strip(); power=row[8].strip(); enc=row[5].strip(); cipher=row[6].strip(); auth=row[7].strip(); essid=row[13].strip() or "<hidden>"
                    security_tokens=set(re.findall(r'[A-Z0-9]+',(enc+' '+auth).upper()))
                    if "WPA2" in security_tokens and "PSK" in security_tokens:
                        sec="WPA2-Personal PSK mixed" if "SAE" in security_tokens else "WPA2-Personal PSK"
                    else:
                        sec="Not WPA2-Personal"
                    rows.append((bssid,ch,sec,power,essid))
            self.observed_clients=sorted(set(clients))
            self.client_combo.configure(values=self.observed_clients)
            if self.client_var.get() not in self.observed_clients:self.client_var.set(self.observed_clients[0] if self.observed_clients else "")
            if self.capture_focused and self.observed_clients and self.deauth_status.get().startswith("Start "):self.deauth_status.set("Choose one of your devices, then Reconnect device. Watch Handshake status for the result.")
            self.sync_workflow_action()
            selected_bssid=self.selected_target["bssid"] if self.selected_target else None
            self.refreshing_targets=True
            current=set(self.table.get_children())
            incoming={row[0]:row for row in rows}
            for stale in current-incoming.keys():self.table.delete(stale)
            for bssid,row in incoming.items():
                if bssid in current:self.table.item(bssid,values=row)
                else:self.table.insert("","end",iid=bssid,values=row)
            if selected_bssid in incoming and self.table.selection()!=(selected_bssid,):self.table.selection_set(selected_bssid)
            self.refreshing_targets=False
        except (OSError,csv.Error,tk.TclError): pass
        finally:self.refreshing_targets=False

    def stop_capture(self):
        if not self.proc or self.stopping:return
        if self.admin_busy:
            if self.stop_pending is None:
                def retry():
                    self.stop_pending=None
                    self.stop_capture()
                self.stop_pending=self.after(100,retry)
            return
        self.stopping=True
        if self.refresh_after:
            self.after_cancel(self.refresh_after);self.refresh_after=None
        self._log("Stopping capture through the authorized session…")
        try:
            self._wait_task(self.proc.stop)
            self._read_csv();self._finish()
            self._log("Capture stopped. Files are ready in the selected folder.")
            if self.pending_focused:
                self.pending_focused=False
                if not self.closing:self.after(250,lambda:self.start_capture(focused=True))
            else:
                if not self.restoring_wifi:self._restore_after_capture()
                if self.pending_network_return and not self.closing and not self.emergency_active:
                    self.pending_network_return=False
                    self.guided.reset_to_network()
                elif self.pending_scan_recovery and not self.closing and not self.emergency_active:
                    self.pending_scan_recovery=False
                    self.coach_panel.use_current()
                    self.recovery_panel.on_capture_finished()
                elif self.capture_focused and not self.closing and not self.emergency_active and not self.restoring_wifi:
                    self.coach_panel.use_current()
                    self.recovery_panel.on_capture_finished()
        except Exception as e:
            self._log(f"Could not stop capture: {e}")
            # Retain the process handle so Stop can be retried after a failure.
            self.stop_btn.configure(state="normal")
            self.scan_stop_btn.configure(state="normal")
            if self.refresh_after is None:self.refresh_after=self.after(2000,self._poll)
        finally:
            self.stopping=False
            self.sync_workflow_action()

    def _finish(self):
        if self.proc:self.status_dock.capture_output(self.proc)
        if self.refresh_after:
            try:self.after_cancel(self.refresh_after)
            except tk.TclError:pass
            self.refresh_after=None
        if getattr(self,"_capture_log",None):
            try:self._capture_log.close()
            except Exception:pass
            self._capture_log=None
        self.proc=None; self.state.configure(text="●  Idle",foreground="#667085")
        self.stop_btn.configure(state="disabled")
        self.scan_stop_btn.configure(state="disabled")
        self.adapter_table.configure(selectmode="browse")
        self.update_interface_controls()
        self.update_workflow()

    def _finish_close(self):
        if self.proc or self.recovery_panel.job_running:
            self.after(350,self._finish_close)
        else:
            try:self._wait_task(self.admin.close)
            except Exception as e:
                self._log(f"Cleanup failed: {e}")
                self.closing=False
                messagebox.showerror(APP,f"Cleanup did not complete:\n{e}\nUse Restore networking before closing.");return
            if hasattr(self,"guided"):self.guided.save_settings()
            self.destroy()

    def close(self):
        self.closing=True
        self.live_advisor.cancel()
        self.coach_panel.close()
        if self.admin_busy:
            self.after(200,self.close);return
        if self.recovery_panel.job_running:self.recovery_panel.pause_save()
        if self.proc:self.stop_capture()
        self._finish_close()

if __name__=="__main__":
    AirWatch().mainloop()
