"""Offline WPA capture analysis and Hashcat UI for AirWatch."""
import gzip
import json
import os
import queue
import re
import select
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from handshake_assistant.devices import discover, preferred_device, recovery_environment
from recovery_session import write_manifest, remember, load_saved, clear_if_current, process_active
from phone_area_codes import STATE_AREA_CODES, STATE_NAMES, NANPA_FILE_DATE

HASHCAT = shutil.which("hashcat")
MAX_EXPANDED_WORDLIST = 2 * 1024**3
DISK_RESERVE = 1024**3
PHONE_MASK = '?2?d?d?d?d?d?d?d?d?d'
PHONE_CHARSET = '23456789'
PHONE_TOTAL = 8_000_000_000
STATE_LINE_TOTAL = 10_000_000
STATE_PHONE_FORMATS = ('Both styles', 'Digits only', 'With dashes')


def state_phone_masks(codes, phone_format):
    """Make one Hashcat mask per area code and requested phone-number style."""
    if phone_format not in STATE_PHONE_FORMATS:
        raise ValueError('Choose a phone number format.')
    plain=[code+'?d'*7 for code in codes]
    dashed=[code+'-'+'?d'*3+'-'+'?d'*4 for code in codes]
    return (plain+dashed if phone_format=='Both styles' else
            dashed if phone_format=='With dashes' else plain)

ROCKYOU = next((Path(p) for p in (
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
) if Path(p).is_file()), None)


def compact_number(value):
    value = int(value)
    if value >= 10**21:
        return f"{value:.2e}"
    for scale, suffix in ((10**15, "quadrillion"), (10**12, "trillion"),
                          (10**9, "billion"), (10**6, "million")):
        if value >= scale:
            return f"{value / scale:,.2f} {suffix}"
    return f"{value:,}"


def duration(seconds):
    if seconds is None or seconds < 0:
        return "Waiting for speed"
    if seconds > 1_000_000 * 365 * 86400:
        return "over a million years"
    if seconds > 365 * 86400:
        return f"about {seconds / (365 * 86400):,.1f} years"
    if seconds >= 86400:
        return f"about {seconds / 86400:,.1f} days"
    if seconds >= 3600:
        return f"about {seconds / 3600:,.1f} hours"
    if seconds >= 60:
        return f"about {seconds / 60:,.0f} minutes"
    return f"about {seconds:,.0f} seconds"


class RecoveryPanel(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=18)
        self.app = app
        self.events = queue.Queue()
        self.estimate_proc = None
        self.hashcat_proc = None
        self.ready_hash = None
        self.run_dir = None
        self.result_path = None
        self.recovered_plain = None
        self.job_started = None
        self.job_running = False
        self.cancel_requested = False
        self.pause_requested = False
        self.saved_session = None
        self.session_manifest = None
        self.pending_capture = None
        self.ready_target_bssid = None
        self.active_target = None
        self.active_options = None
        self.sample_inflight = False
        self.last_sample_at = 0
        self.sample_keyspaces = {}
        self.devices=[]
        self.device_var=tk.StringVar(value="Detecting GPUs…")
        self.gpu_status=tk.StringVar(value="Looking for Hashcat devices…")
        self.fast_workload=tk.BooleanVar(value=False)
        self.optimized=tk.BooleanVar(value=False)
        self.temperature=tk.IntVar(value=80)
        self.runtime=tk.IntVar(value=0)
        self.capture_path = tk.StringVar()
        self.method = tk.StringVar(value="wordlist")
        self.phone_state = tk.StringVar(value="Illinois")
        self.phone_format = tk.StringVar(value="Both styles")
        self.wordlist_path = tk.StringVar(value=str(ROCKYOU) if ROCKYOU else "")
        self.lower = tk.BooleanVar(value=True)
        self.upper = tk.BooleanVar(value=False)
        self.digits = tk.BooleanVar(value=True)
        self.symbols = tk.BooleanVar(value=False)
        self.min_len = tk.IntVar(value=8)
        self.max_len = tk.IntVar(value=10)
        self.target_var = tk.StringVar(value="Select an access point in the Scan tab first.")
        self.tool_var = tk.StringVar()
        self.analysis_var = tk.StringVar(value="Waiting for a capture to analyze.")
        self.keyspace_var = tk.StringVar(value="Select an attack method to see the search size.")
        self.estimate_var = tk.StringVar(value="Pre-run estimate: click Estimate after analyzing a capture.")
        self.state_var = tk.StringVar(value="Idle")
        self.progress_var = tk.StringVar(value="0%")
        self.current_guess_var = tk.StringVar(value="Waiting for Hashcat…")
        self.tried_var = tk.StringVar(value="0")
        self.total_var = tk.StringVar(value="—")
        self.speed_var = tk.StringVar(value="Speed: —")
        self.eta_var = tk.StringVar(value="ETA: —")
        self.elapsed_var = tk.StringVar(value="Elapsed: —")
        self.result_var = tk.StringVar(value="No passphrase recovered yet.")
        self._build()
        self.refresh_tools()
        self.update_estimate()
        self.after(250, self._pump)
        self.after(500,self.refresh_devices)
        self.after(300,self.discover_saved_session)
        self.bind_all("<MouseWheel>",self._wheel,add="+")
        self.bind_all("<Button-4>",self._wheel,add="+")
        self.bind_all("<Button-5>",self._wheel,add="+")

    def _build(self):
        canvas=tk.Canvas(self,highlightthickness=0,background="#f4f6f8")
        scroll=ttk.Scrollbar(self,orient="vertical",command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left",fill="both",expand=True)
        scroll.pack(side="right",fill="y")
        content=ttk.Frame(canvas,padding=(0,0,8,12))
        window=canvas.create_window((0,0),window=content,anchor="nw")
        content.bind("<Configure>",lambda _e:canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",lambda e:canvas.itemconfigure(window,width=e.width))
        canvas.bind("<Button-4>",lambda _e:canvas.yview_scroll(-3,"units"))
        canvas.bind("<Button-5>",lambda _e:canvas.yview_scroll(3,"units"))
        self.canvas=canvas
        content.columnconfigure(0,weight=1)
        header = ttk.Frame(content); header.pack(fill="x")
        ttk.Label(header, text="Offline recovery", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="Selected access point only", style="Sub.TLabel").pack(side="right")
        ttk.Label(content, text="Analyze the saved capture, then choose a wordlist or a mask. Hashcat runs locally and reports live progress.", style="Sub.TLabel").pack(anchor="w", pady=(3,12))

        top = ttk.Frame(content, style="Card.TFrame", padding=14); top.pack(fill="x")
        ttk.Label(top, text="1  Verify the capture", style="CardHead.TLabel").pack(anchor="w")
        ttk.Label(top, textvariable=self.target_var, style="Card.TLabel").pack(anchor="w", pady=(7,5))
        caprow = ttk.Frame(top, style="Card.TFrame"); caprow.pack(fill="x")
        ttk.Entry(caprow, textvariable=self.capture_path).pack(side="left", fill="x", expand=True)
        ttk.Button(caprow, text="Browse capture…", command=self.browse_capture).pack(side="left", padx=(8,0))
        ttk.Button(caprow, text="Use last capture", command=self.use_last_capture).pack(side="left", padx=(8,0))
        deps = ttk.Frame(top, style="Card.TFrame"); deps.pack(fill="x", pady=(8,0))
        ttk.Label(deps, textvariable=self.tool_var, style="Card.TLabel").pack(side="left", fill="x", expand=True)
        self.install_btn = ttk.Button(deps, text="Install hcxtools", command=self.install_converter)
        self.install_btn.pack(side="right")
        act = ttk.Frame(top, style="Card.TFrame"); act.pack(fill="x", pady=(8,0))
        self.analyze_btn = ttk.Button(act, text="Analyze selected capture", command=self.analyze)
        self.analyze_btn.pack(side="left")
        ttk.Label(act, textvariable=self.analysis_var, style="Card.TLabel").pack(side="left", padx=12)

        mid = ttk.Frame(content); mid.pack(fill="x", pady=(12,0))
        options = ttk.Frame(mid, style="Card.TFrame", padding=14); options.pack(side="left", fill="both", expand=True)
        ttk.Label(options, text="2  Choose how to search", style="CardHead.TLabel").pack(anchor="w")
        methods = ttk.Frame(options, style="Card.TFrame"); methods.pack(anchor="w", pady=(9,5))
        ttk.Radiobutton(methods, text="Wordlist", variable=self.method, value="wordlist", command=self.update_estimate).pack(side="left")
        ttk.Radiobutton(methods, text="Brute force mask", variable=self.method, value="mask", command=self.update_estimate).pack(side="left", padx=(18,0))
        ttk.Radiobutton(methods, text="N#########", variable=self.method, value="phone", command=self.update_estimate).pack(side="left", padx=(18,0))
        ttk.Radiobutton(methods, text="By state", variable=self.method, value="state_phone", command=self.update_estimate).pack(side="left", padx=(18,0))
        state_row=ttk.Frame(options,style="Card.TFrame");state_row.pack(anchor="w",pady=(2,4))
        ttk.Label(state_row,text="State",style="Card.TLabel").pack(side="left",padx=(0,7))
        self.state_combo=ttk.Combobox(state_row,textvariable=self.phone_state,values=STATE_NAMES,state="readonly",width=24)
        self.state_combo.pack(side="left")
        self.state_combo.bind("<<ComboboxSelected>>",lambda _e:self.update_estimate())
        ttk.Label(state_row,text="Format",style="Card.TLabel").pack(side="left",padx=(16,7))
        self.phone_format_combo=ttk.Combobox(state_row,textvariable=self.phone_format,
                                              values=STATE_PHONE_FORMATS,state="readonly",width=17)
        self.phone_format_combo.pack(side="left")
        self.phone_format_combo.bind("<<ComboboxSelected>>",lambda _e:self.update_estimate())
        wordrow = ttk.Frame(options, style="Card.TFrame"); wordrow.pack(fill="x", pady=(4,4))
        ttk.Entry(wordrow, textvariable=self.wordlist_path).pack(side="left", fill="x", expand=True)
        ttk.Button(wordrow, text="Choose list…", command=self.browse_wordlist).pack(side="left", padx=(6,0))
        ttk.Button(wordrow, text="Rockyou", command=self.use_rockyou).pack(side="left", padx=(6,0))
        ttk.Label(options,text="Compressed lists: maximum 2 GiB expanded; keeps 1 GiB of disk space free.",style="Card.TLabel").pack(anchor="w",pady=(3,6))
        chars = ttk.Frame(options, style="Card.TFrame"); chars.pack(fill="x", pady=(6,2))
        for label,var in (("a–z",self.lower),("A–Z",self.upper),("0–9",self.digits),("Symbols",self.symbols)):
            ttk.Checkbutton(chars, text=label, variable=var, command=self.update_estimate).pack(side="left", padx=(0,12))
        lengths = ttk.Frame(options, style="Card.TFrame"); lengths.pack(fill="x", pady=(4,4))
        ttk.Label(lengths, text="Length from", style="Card.TLabel").pack(side="left")
        ttk.Spinbox(lengths, from_=8, to=63, width=4, textvariable=self.min_len, command=self.update_estimate).pack(side="left", padx=(5,8))
        ttk.Label(lengths, text="to", style="Card.TLabel").pack(side="left")
        ttk.Spinbox(lengths, from_=8, to=63, width=4, textvariable=self.max_len, command=self.update_estimate).pack(side="left", padx=(5,0))
        ttk.Button(lengths,text="10-digit numeric preset",command=self.numeric_preset).pack(side="left",padx=12)
        self.min_len.trace_add("write", lambda *_: self.update_estimate())
        self.max_len.trace_add("write", lambda *_: self.update_estimate())
        ttk.Label(options, textvariable=self.keyspace_var, style="Card.TLabel", wraplength=560).pack(anchor="w", pady=(7,0))
        estimate_row=ttk.Frame(options,style="Card.TFrame");estimate_row.pack(fill="x",pady=(8,0))
        self.estimate_btn=ttk.Button(estimate_row,text="Estimate time",command=self.estimate_time)
        self.estimate_btn.pack(side="left")
        ttk.Label(estimate_row,textvariable=self.estimate_var,style="Card.TLabel",wraplength=420).pack(side="left",padx=(10,0))

        advice = ttk.Frame(mid, style="Card.TFrame", padding=14); advice.pack(side="left", fill="both", padx=(12,0))
        ttk.Label(advice, text="Suggested order", style="CardHead.TLabel").pack(anchor="w")
        ttk.Label(advice, text="1. Start with rockyou or your own focused list.\n\n2. If needed, try a narrow mask based on known length or character pattern.\n\n3. Add uppercase and symbols only when justified: each added character choice expands the search.\n\nETA estimates time to exhaust the chosen search. Recovery may happen earlier or may find no match. Speed settles after startup.", style="Card.TLabel", wraplength=270, justify="left").pack(anchor="w", pady=(9,0))

        gpu=ttk.Frame(content,style="Card.TFrame",padding=14);gpu.pack(fill="x",pady=(12,0))
        ttk.Label(gpu,text="3  GPU and performance",style="CardHead.TLabel").pack(anchor="w")
        device_row=ttk.Frame(gpu,style="Card.TFrame");device_row.pack(fill="x",pady=8)
        self.device_combo=ttk.Combobox(device_row,textvariable=self.device_var,state="readonly")
        self.device_combo.pack(side="left",fill="x",expand=True)
        self.device_combo.bind("<<ComboboxSelected>>",lambda _e:self.update_estimate())
        self.refresh_gpu_btn=ttk.Button(device_row,text="Refresh GPUs",command=self.refresh_devices)
        self.refresh_gpu_btn.pack(side="left",padx=8)
        ttk.Label(gpu,textvariable=self.gpu_status,style="Card.TLabel",wraplength=1000).pack(anchor="w")
        performance=ttk.Frame(gpu,style="Card.TFrame");performance.pack(fill="x",pady=8)
        ttk.Checkbutton(performance,text="High workload (-w 3)",variable=self.fast_workload,command=self.update_estimate).pack(side="left")
        ttk.Checkbutton(performance,text="Optimized kernels (-O)",variable=self.optimized,command=self.update_estimate).pack(side="left",padx=16)
        ttk.Label(performance,text="Stop at °C",style="Card.TLabel").pack(side="left")
        ttk.Spinbox(performance,from_=60,to=90,width=4,textvariable=self.temperature).pack(side="left",padx=6)
        ttk.Label(performance,text="Time limit (seconds; 0 = none)",style="Card.TLabel").pack(side="left",padx=(12,4))
        ttk.Spinbox(performance,from_=0,to=86400,width=7,textvariable=self.runtime).pack(side="left")
        ttk.Label(gpu,text="Default: GeForce when available, or the fastest GPU when all have saved measurements. High workload may reduce desktop responsiveness. Optimized kernels can restrict password lengths; Hashcat reports its supported range. Thermal monitoring must be available for the temperature limit.",style="Card.TLabel",wraplength=1050).pack(anchor="w")

        run = ttk.Frame(content, style="Card.TFrame", padding=14); run.pack(fill="both", expand=True, pady=(12,0))
        topbar = ttk.Frame(run, style="Card.TFrame"); topbar.pack(fill="x")
        ttk.Label(topbar, text="4  Run and monitor", style="CardHead.TLabel").pack(side="left")
        self.start_btn = ttk.Button(topbar, text="Start Hashcat", command=self.start_attack)
        self.start_btn.pack(side="right")
        ttk.Button(topbar,text="Open results folder",command=self.open_results).pack(side="right",padx=(0,7))
        self.resume_btn = ttk.Button(topbar, text="▶ Continue old search", command=self.resume_saved, state="disabled")
        self.resume_btn.pack(side="right", padx=(0,7))
        ttk.Button(topbar,text='Open saved…',command=self.open_saved_session).pack(side='right',padx=(0,7))
        self.pause_btn = ttk.Button(topbar, text="Ⅱ Pause & save", command=self.pause_save, state="disabled")
        self.pause_btn.pack(side="right", padx=(0,7))
        self.stop_btn = ttk.Button(topbar, text="Stop", command=self.stop_attack, state="disabled")
        self.stop_btn.pack(side="right", padx=(0,7))
        ttk.Label(run, textvariable=self.state_var, style="Card.TLabel").pack(anchor="w", pady=(9,4))
        barrow = ttk.Frame(run, style="Card.TFrame"); barrow.pack(fill="x")
        self.progress = ttk.Progressbar(barrow, mode="determinate", maximum=100)
        self.progress.pack(side="left", fill="x", expand=True)
        ttk.Label(barrow, textvariable=self.progress_var, style="Card.TLabel", width=9).pack(side="left", padx=(9,0))
        metrics = ttk.Frame(run, style="Card.TFrame"); metrics.pack(fill="x", pady=(7,0))
        for var in (self.speed_var,self.eta_var,self.elapsed_var):
            ttk.Label(metrics,textvariable=var,style="Card.TLabel").pack(side="left",padx=(0,24))
        live = ttk.Frame(run, style="Card.TFrame"); live.pack(fill="x", pady=(9,0))
        ttk.Label(live,text="Guess sample",style="Card.TLabel").pack(side="left",padx=(0,7))
        ttk.Entry(live,textvariable=self.current_guess_var,state="readonly",width=31).pack(side="left",padx=(0,18))
        for title,var in (("Tried",self.tried_var),("Total",self.total_var)):
            ttk.Label(live,text=title+":",style="Card.TLabel").pack(side="left",padx=(0,4))
            ttk.Label(live,textvariable=var,style="CardHead.TLabel").pack(side="left",padx=(0,18))
        resultrow = ttk.Frame(run, style="Card.TFrame"); resultrow.pack(fill="x", pady=(10,3))
        ttk.Label(resultrow, textvariable=self.result_var, style="Card.TLabel").pack(side="left")
        self.reveal_btn=ttk.Button(resultrow,text="Reveal",command=self.toggle_reveal,state="disabled")
        self.reveal_btn.pack(side="left",padx=(9,0))
        self.output = tk.Text(run, height=5, wrap="word", relief="flat", bg="#f8fafc", fg="#344054", font=("TkFixedFont",9), state="disabled")
        self.output.pack(fill="both",expand=True,pady=(5,0))

    def refresh_devices(self):
        if self.job_running:return
        self.refresh_gpu_btn.state(["disabled"])
        self.gpu_status.set("Detecting GPUs…")
        def worker():
            try:self.events.put(("devices",discover()[0]))
            except Exception as e:self.events.put(("device_error",str(e)))
        threading.Thread(target=worker,daemon=True).start()

    def performance_args(self, estimate=False):
        device=next((d for d in self.devices if d.label==self.device_var.get()),None)
        if not device:raise ValueError("Choose an available GPU. GeForce is preferred; another GPU requires your explicit selection.")
        try:temperature=int(self.temperature.get());runtime=int(self.runtime.get())
        except (ValueError,tk.TclError):raise ValueError("Enter valid temperature and time limits.")
        if not 60<=temperature<=90 or not 0<=runtime<=86400:raise ValueError("Temperature must be 60–90 °C; runtime must be 0–86400 seconds.")
        args=["-d",device.id,"-w","3" if self.fast_workload.get() else "2","--hwmon-temp-abort",str(temperature)]
        if self.optimized.get():args.append("-O")
        if runtime and not estimate:args.extend(["--runtime",str(runtime)])
        return args

    def open_results(self):
        folder=Path(self.run_dir) if self.run_dir else None
        if not folder or not folder.exists():
            messagebox.showinfo("AirWatch","Analyze a capture first to create a results folder.");return
        try:subprocess.Popen(["xdg-open",str(folder)])
        except OSError as exc:messagebox.showerror("AirWatch",f"Could not open results folder:\n{exc}")

    def _wheel(self, event):
        if self.app.main_tabs.select()!=str(self):return
        if getattr(event,"num",None)==4:amount=-3
        elif getattr(event,"num",None)==5:amount=3
        else:amount=-3 if event.delta>0 else 3
        self.canvas.yview_scroll(amount,"units")

    def _log(self, message):
        self.output.configure(state="normal")
        self.output.insert("end", message.rstrip()+"\n")
        self.output.see("end")
        self.output.configure(state="disabled")

    def refresh_tools(self):
        bundled=Path(__file__).resolve().parent/"vendor"/"hcxpcapngtool"
        self.converter = shutil.which("hcxpcapngtool") or (str(bundled) if bundled.is_file() and os.access(bundled,os.X_OK) else None)
        if self.converter:
            source="bundled" if self.converter==str(bundled) else "installed"
            self.tool_var.set(f"hcxpcapngtool is ready ({source}) · Hashcat " + ("ready" if HASHCAT else "missing"))
            self.install_btn.configure(state="disabled")
        else:
            self.tool_var.set("hcxpcapngtool is needed to convert .cap captures to Hashcat format.")
            self.install_btn.configure(state="normal" if shutil.which("apt-get") else "disabled")

    def install_converter(self):
        if not shutil.which("apt-get"):
            messagebox.showerror("AirWatch", "Install the hcxtools package with your Linux package manager.")
            return
        self.install_btn.configure(state="disabled")
        self.tool_var.set("Installing hcxtools through the system package manager…")
        def worker():
            try:
                result=self.app._run_privileged([shutil.which("apt-get"),"install","-y","hcxtools"],timeout=300)
                self.events.put(("install",result.returncode,(result.stdout+result.stderr)[-1500:]))
            except Exception as exc:
                self.events.put(("install",-1,str(exc)))
        threading.Thread(target=worker,daemon=True).start()

    def browse_capture(self):
        path=filedialog.askopenfilename(title="Choose a saved capture",filetypes=[("Wireless captures","*.cap *.pcap *.pcapng *.hc22000"),("All files","*")])
        if path:
            self.capture_path.set(path)
            self.ready_hash=None
            self.analysis_var.set("Click Analyze selected capture.")

    def use_last_capture(self):
        prefix=self.app.capture_prefix
        if not prefix:
            messagebox.showinfo("AirWatch","No capture has been made in this session yet.");return
        path=Path(prefix+"-01.cap")
        if not path.exists():
            messagebox.showinfo("AirWatch",f"Capture file has not appeared yet:\n{path}");return
        self.capture_path.set(str(path))
        self.analysis_var.set("Click Analyze selected capture.")

    def on_capture_finished(self):
        if self.job_running:
            self.defer_capture(self.app.capture_prefix,self.app.selected_target)
            return
        self.use_last_capture()
        self.app.main_tabs.select(self)
        if self.capture_path.get():
            self.analyze()

    def defer_capture(self,prefix,target):
        """Keep a new capture separate from the currently running search."""
        if not prefix or not target:return
        path=Path(prefix+'-01.cap')
        if path.is_file():
            self.pending_capture=(str(path),dict(target))
            self.analysis_var.set('New capture saved. Check it after the current search stops.')
            self.app._log('New capture saved for later analysis; the current password search continues.')

    def analyze_pending_capture(self):
        if self.job_running or not self.pending_capture:return
        path,target=self.pending_capture
        if not Path(path).is_file():
            self.analysis_var.set('The new capture file is missing.')
            return
        self.pending_capture=None
        self.app.selected_target=dict(target)
        self.active_target=dict(target)
        self.app.client_suitability.select(self.app.selected_target)
        self.capture_path.set(path)
        self.target_var.set(f"Selected: {target['essid']}  ·  {target['bssid']}")
        self.ready_hash=None
        self.ready_target_bssid=None
        self.analyze()

    def ready_for_current_target(self):
        current=re.sub(r'[^0-9a-fA-F]','',(self.app.selected_target or {}).get('bssid','')).lower()
        return bool(self.ready_hash and (not self.ready_target_bssid or current==self.ready_target_bssid))

    def use_rockyou(self):
        if ROCKYOU:
            self.wordlist_path.set(str(ROCKYOU))
            self.method.set("wordlist")
            self.update_estimate()
        else:
            messagebox.showinfo("AirWatch","rockyou was not found in /usr/share/wordlists. Choose a wordlist file.")

    def browse_wordlist(self):
        path=filedialog.askopenfilename(title="Choose a wordlist",filetypes=[("Wordlists","*.txt *.dic *.dict *.gz"),("All files","*")])
        if path:
            self.wordlist_path.set(path)
            self.method.set("wordlist")
            self.update_estimate()

    def numeric_preset(self):
        if self.job_running:return
        self.method.set("mask")
        self.lower.set(False);self.upper.set(False);self.digits.set(True);self.symbols.set(False)
        self.min_len.set(10);self.max_len.set(10)
        self.update_estimate()

    def _charset(self):
        selected=[("?l",26,self.lower.get()),("?u",26,self.upper.get()),("?d",10,self.digits.get()),("?s",33,self.symbols.get())]
        return "".join(code for code,_,enabled in selected if enabled),sum(size for _,size,enabled in selected if enabled)

    def update_estimate(self):
        self.estimate_var.set("Pre-run estimate: click Estimate after analyzing a capture.")
        if self.method.get()=="wordlist":
            path=self.wordlist_path.get()
            self.keyspace_var.set("Wordlist search: one pass through the selected list. Live speed and ETA appear after Hashcat starts." if path else "Choose a wordlist, or click Rockyou.")
            return
        if self.method.get()=="phone":
            self.keyspace_var.set("N######### · N is 2–9, then any 9 digits · 8 billion combinations. No dashes; unassigned numbers are included.")
            return
        if self.method.get()=="state_phone":
            state=self.phone_state.get();codes=STATE_AREA_CODES.get(state,())
            try:masks=state_phone_masks(codes,self.phone_format.get())
            except ValueError:
                self.keyspace_var.set('Choose a phone number format.');return
            self.keyspace_var.set(f"{state} · {len(codes)} area codes · {self.phone_format.get().lower()} · {compact_number(len(masks)*STATE_LINE_TOTAL)} combinations. Codes: {NANPA_FILE_DATE}.")
            return
        try:
            minimum=int(self.min_len.get());maximum=int(self.max_len.get())
        except (ValueError,tk.TclError):
            self.keyspace_var.set("Enter a minimum and maximum length from 8 to 63.");return
        charset,size=self._charset()
        if not charset or not 8<=minimum<=maximum<=63:
            self.keyspace_var.set("Choose at least one character group and a valid length range from 8 to 63.");return
        total=sum(size**length for length in range(minimum,maximum+1))
        guidance=" This is a very large search; narrow the range or character groups." if total>10**12 else ""
        self.keyspace_var.set(f"{size} characters · lengths {minimum}–{maximum} · {compact_number(total)} candidates. Every extra position multiplies the work roughly by {size}.{guidance}")

    def analyze(self):
        if self.job_running:
            self.analysis_var.set("Stop the current Hashcat run before analyzing another capture.");return
        target=self.app.selected_target
        if not target:
            self.analysis_var.set("Select an access point in the Scan tab first.");return
        source=Path(self.capture_path.get()).expanduser()
        if not source.is_file():
            self.analysis_var.set("Choose an existing .cap or .hc22000 file.");return
        if source.suffix.lower()!=".hc22000" and not self.converter:
            self.analysis_var.set("Converter missing. Click Install hcxtools, then Analyze again.");return
        bssid=re.sub(r"[^0-9a-fA-F]","",target["bssid"]).lower()
        if len(bssid)!=12:
            self.analysis_var.set("Selected BSSID is invalid. Select the access point again.");return
        self.target_var.set(f"Selected: {target['essid']}  ·  {target['bssid']}")
        self.app.emergency_active=False
        self.analysis_var.set("Converting and checking capture…")
        self.analyze_btn.configure(state="disabled")
        self.ready_hash=None
        folder=Path(self.app.outdir.get()).expanduser()
        def worker():
            try:
                run_dir=folder/("recovery_"+time.strftime("%Y%m%d_%H%M%S")+"_"+str(time.time_ns()%1000000))
                run_dir.mkdir(parents=True,mode=0o700,exist_ok=True)
                if source.suffix.lower()==".hc22000":
                    converted=source
                else:
                    converted=run_dir/"extracted.hc22000"
                    if self.app.emergency_active:raise RuntimeError('Analysis cancelled by emergency stop.')
                    result=subprocess.run([self.converter,"-o",str(converted),str(source)],capture_output=True,text=True,timeout=120)
                    if result.returncode or not converted.exists():
                        conversion_output=result.stdout+result.stderr
                        if 'KDV:0' in conversion_output and 'not supported by hashcat/JtR' in conversion_output:
                            raise RuntimeError('Captured an exchange that this recovery method cannot use. It requires a WPA2-Personal client connection; capturing the same exchange again will not help.')
                        raise RuntimeError((result.stdout+result.stderr).strip()[-1200:] or "The converter found no usable WPA records.")
                selected=[];eapol=0;pmkid=0
                for line in converted.read_text(errors="replace").splitlines():
                    parts=line.strip().split("*")
                    if len(parts)>=6 and parts[0]=="WPA" and parts[1] in ("01","02") and parts[3].lower()==bssid:
                        selected.append(line.strip())
                        if parts[1]=="02":eapol+=1
                        else:pmkid+=1
                if not selected:
                    raise RuntimeError("No extractable EAPOL handshake or PMKID record matched the selected BSSID. Capture longer or choose the correct access point.")
                unique=list(dict.fromkeys(selected))
                if self.app.emergency_active:raise RuntimeError('Analysis cancelled by emergency stop.')
                filtered=run_dir/(bssid+".hc22000")
                filtered.write_text("\n".join(unique)+"\n")
                self.events.put(("analysis",str(filtered),str(run_dir),eapol,pmkid,bssid,str(source)))
            except Exception as exc:
                self.events.put(("analysis_error",str(exc)))
        threading.Thread(target=worker,daemon=True).start()

    def _attack_options(self):
        if self.method.get()=="wordlist":
            path=Path(self.wordlist_path.get()).expanduser()
            if not path.is_file():raise ValueError("Choose an existing wordlist or click Rockyou.")
            return {"mode":"wordlist","path":str(path)}
        if self.method.get()=="phone":
            return {"mode":"phone","mask":PHONE_MASK,"charset":PHONE_CHARSET,"total":PHONE_TOTAL}
        if self.method.get()=="state_phone":
            state=self.phone_state.get();codes=STATE_AREA_CODES.get(state)
            if not codes:raise ValueError("Choose a state with available area codes.")
            masks=state_phone_masks(codes,self.phone_format.get())
            return {"mode":"state_phone","state":state,"codes":list(codes),
                    "phone_format":self.phone_format.get(),"masks":masks,
                    "total":len(masks)*STATE_LINE_TOTAL}
        try:
            minimum=int(self.min_len.get());maximum=int(self.max_len.get())
        except (ValueError,tk.TclError):
            raise ValueError("Enter valid mask lengths.")
        charset,size=self._charset()
        if not charset or not 8<=minimum<=maximum<=63:
            raise ValueError("Choose character groups and lengths between 8 and 63.")
        return {"mode":"mask","charset":charset,"size":size,"minimum":minimum,"maximum":maximum}

    def estimate_time(self):
        if self.job_running:
            self.estimate_var.set("Use the live ETA while a search is running.");return
        if not HASHCAT:
            self.estimate_var.set("Hashcat is not installed.");return
        if not self.ready_hash:
            self.estimate_var.set("Analyze a capture first.");return
        try:
            options=self._attack_options()
            performance=self.performance_args(estimate=True)
        except ValueError as exc:
            self.estimate_var.set(str(exc));return
        self.estimate_btn.configure(state="disabled")
        self.job_running=True
        self.app.emergency_active=False
        self.cancel_requested=False
        self.start_btn.state(["disabled"]);self.stop_btn.state(["!disabled"])
        self.state_var.set("Measuring selected GPU speed…")
        self.estimate_var.set("Measuring WPA speed on the selected GPU…")
        hashfile=self.ready_hash
        def worker():
            try:
                sample_mask="?d"*8
                self.estimate_proc=subprocess.Popen([HASHCAT,"-m","22000","-a","3","--speed-only","--machine-readable",*performance,hashfile,sample_mask],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True,env=recovery_environment())
                if self.cancel_requested:os.killpg(self.estimate_proc.pid,signal.SIGINT)
                try:
                    stdout,stderr=self.estimate_proc.communicate(timeout=90)
                except subprocess.TimeoutExpired:
                    os.killpg(self.estimate_proc.pid,signal.SIGKILL)
                    self.estimate_proc.communicate()
                    raise RuntimeError("GPU speed estimate exceeded 90 seconds and was stopped.")
                proc=self.estimate_proc
                self.estimate_proc=None
                if self.cancel_requested:raise RuntimeError("Estimate cancelled.")
                lines=(stdout+"\n"+stderr).splitlines()
                speeds=[]
                for line in lines:
                    match=re.search(r"(\d+):(\d+)\s*$",line)
                    if match:speeds.append(int(match.group(2)))
                if proc.returncode or not speeds:
                    raise RuntimeError("Hashcat could not measure a usable speed: "+" ".join(lines[-8:])[-900:])
                speed=sum(speeds)
                if options["mode"]=="wordlist":
                    path=Path(options["path"])
                    opener=gzip.open if path.suffix.lower()==".gz" else open
                    count=0;expanded=0
                    with opener(path,"rb") as stream:
                        for block in iter(lambda:stream.read(1024*1024),b""):
                            if self.cancel_requested:raise RuntimeError("Estimate cancelled.")
                            expanded+=len(block)
                            if path.suffix.lower()==".gz" and expanded>MAX_EXPANDED_WORDLIST:raise RuntimeError("Compressed wordlist exceeds the 2 GiB expansion limit.")
                            count+=block.count(b"\n")
                    total=count
                elif options["mode"]=="phone":
                    total=options["total"]
                elif options["mode"]=="state_phone":
                    total=options["total"]
                else:
                    total=sum(options["size"]**n for n in range(options["minimum"],options["maximum"]+1))
                self.events.put(("estimate",speed,total))
            except Exception as exc:
                self.events.put(("estimate_error",str(exc)))
        threading.Thread(target=worker,daemon=True).start()

    def start_attack(self):
        if not HASHCAT:
            messagebox.showerror("AirWatch","Hashcat is not installed. Install it with your package manager.");return
        if not self.ready_hash or self.hashcat_proc or self.job_running:
            messagebox.showinfo("AirWatch","Analyze a capture first, or wait for the current run to finish.");return
        if not self.ready_for_current_target():
            messagebox.showinfo('AirWatch','Check the selected network’s capture before starting its password search.')
            return
        if self.saved_session and Path(self.saved_session['restore_file']).is_file():
            if not messagebox.askyesno('Saved search exists',
                    'Start a new search with the pattern selected now? The old search uses its original pattern and its checkpoint stays in its results folder.'):
                return
        try:
            options=self._attack_options()
            performance=self.performance_args()
        except ValueError as exc:
            messagebox.showerror("AirWatch",str(exc));return
        self.job_running=True
        self.active_options=options
        self.active_target=dict(self.app.selected_target or {})
        self.app.emergency_active=False
        self.cancel_requested=False
        self.pause_requested=False
        self.canvas.yview_moveto(1.0)
        self.job_started=time.monotonic()
        self.recovered_plain=None
        self.result_var.set("No passphrase recovered yet.")
        self.reveal_btn.configure(state="disabled",text="Reveal")
        self.start_btn.configure(state="disabled")
        self.resume_btn.configure(state="disabled")
        self.pause_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.configure(value=0)
        self.progress_var.set("0%")
        self.current_guess_var.set("Waiting for Hashcat…")
        self.tried_var.set("0")
        self.total_var.set("—")
        self.speed_var.set("Speed: —")
        self.eta_var.set("ETA: waiting for speed")
        self.state_var.set("Preparing the search…")
        self.app.update_workflow(stage=5,note="Hashcat is preparing the selected offline recovery search.")
        run_dir=Path(self.run_dir)
        attack_dir=run_dir/("attack_"+time.strftime("%Y%m%d_%H%M%S")+"_"+str(time.time_ns()%1000000))
        try:
            attack_dir.mkdir(mode=0o700)
        except OSError as exc:
            self.job_running=False
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.state_var.set(f"Could not create results folder: {exc}")
            return
        self.result_path=attack_dir/"recovered.txt"
        hashfile=self.ready_hash
        session_name="airwatch_"+time.strftime("%Y%m%d_%H%M%S")+str(time.time_ns()%1000)
        restore_file=attack_dir/"hashcat.restore"
        self.session_manifest=attack_dir/"airwatch-session.json"
        metadata={'version':1,'session':session_name,'restore_file':str(restore_file),
                  'hashfile':str(hashfile),'result_path':str(self.result_path),
                  'run_dir':str(run_dir),'capture_path':self.capture_path.get(),
                  'target':dict(self.app.selected_target or {}),'attack_options':options,
                  'runtime_limit':int(self.runtime.get()),'pid':0,'status':'preparing'}
        def worker():
            try:
                args=[HASHCAT,*performance,"-m","22000","--status","--status-json","--status-timer","2", "--session",session_name,
                      "--restore-file-path",str(restore_file),"--potfile-disable","--outfile",str(self.result_path),"--outfile-format","2"]
                if options["mode"]=="wordlist":
                    wordlist=Path(options["path"])
                    if wordlist.suffix.lower()==".gz":
                        unpacked=attack_dir/"wordlist.txt"
                        temp=attack_dir/"wordlist.txt.part"
                        expanded=0
                        try:
                            with wordlist.open("rb") as raw, gzip.GzipFile(fileobj=raw) as stream, temp.open("xb") as out:
                                while True:
                                    if self.cancel_requested:raise RuntimeError("Preparation cancelled.")
                                    block=stream.read(1024*1024)
                                    if not block:break
                                    expanded+=len(block)
                                    if expanded>MAX_EXPANDED_WORDLIST:raise RuntimeError("Compressed wordlist exceeds the 2 GiB expansion limit.")
                                    if shutil.disk_usage(attack_dir).free<len(block)+DISK_RESERVE:raise RuntimeError("Wordlist extraction stopped to preserve 1 GiB of free disk space.")
                                    out.write(block)
                                    self.events.put(("prepare",min(99,round(raw.tell()/wordlist.stat().st_size*100))))
                            os.replace(temp,unpacked)
                        finally:
                            temp.unlink(missing_ok=True)
                        wordlist=unpacked
                    args += ["-a","0",hashfile,str(wordlist)]
                    metadata['wordlist_path']=str(wordlist)
                    count=0
                    with wordlist.open("rb") as f:
                        for block in iter(lambda:f.read(1024*1024),b""):
                            if self.cancel_requested:raise RuntimeError("Preparation cancelled.")
                            count+=block.count(b"\n")
                    self.events.put(("keyspace",count))
                elif options["mode"]=="phone":
                    self.events.put(("keyspace",options["total"]))
                    args += ["-a","3","-2",options["charset"],hashfile,options["mask"]]
                elif options["mode"]=="state_phone":
                    maskfile=attack_dir/"state-phone-masks.hcmask"
                    maskfile.write_text("".join(mask+"\n" for mask in options["masks"]))
                    metadata['mask_file_path']=str(maskfile)
                    self.events.put(("keyspace",options["total"]))
                    args += ["-a","3",hashfile,str(maskfile)]
                else:
                    mask="?1"*options["maximum"]
                    total=sum(options["size"]**n for n in range(options["minimum"],options["maximum"]+1))
                    self.events.put(("keyspace",total))
                    args += ["-a","3","-1",options["charset"],"--increment","--increment-min",str(options["minimum"]),"--increment-max",str(options["maximum"]),hashfile,mask]
                if self.cancel_requested:raise RuntimeError("Preparation cancelled.")
                write_manifest(self.session_manifest,metadata)
                self.events.put(("hashcat_start",))
                self.events.put(("log","Starting Hashcat against the selected access point.\n"))
                self._run_hashcat(args)
            except Exception as exc:
                self.hashcat_proc=None
                self.events.put(("attack_error",str(exc)))
        threading.Thread(target=worker,daemon=True).start()

    def _run_hashcat(self,args):
        process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,text=True,bufsize=1,
                                 start_new_session=True,env=recovery_environment())
        self.hashcat_proc=process
        try:
            metadata=json.loads(Path(self.session_manifest).read_text())
            metadata.update(pid=process.pid,status='running')
            write_manifest(self.session_manifest,metadata)
            remember(self.session_manifest)
        except (OSError,ValueError) as exc:
            self.events.put(("log","Could not save session details: "+str(exc)))
        if self.pause_requested:self._request_checkpoint(process)
        result_path=self.result_path
        def stop_on_first_match():
            while process.poll() is None and not self.cancel_requested:
                try:found=result_path.is_file() and result_path.stat().st_size>0
                except OSError:found=False
                if found:
                    self.events.put(("log","Password found. Stopping the search.\n"))
                    try:os.killpg(process.pid,signal.SIGINT)
                    except ProcessLookupError:pass
                    return
                time.sleep(.25)
        threading.Thread(target=stop_on_first_match,daemon=True).start()
        for line in process.stdout:
            line=line.replace("\r","").strip()
            if not line:continue
            if "{" in line:
                try:
                    data,_=json.JSONDecoder().raw_decode(line[line.index("{"):])
                    if isinstance(data,dict) and "progress" in data:
                        self.events.put(("status",data));continue
                except json.JSONDecodeError:pass
            if line.startswith("[s]tatus "):continue
            self.events.put(("log",line))
        code=process.wait()
        self.hashcat_proc=None
        self.events.put(("done",code))

    def _request_checkpoint(self,process):
        try:
            if process.poll() is None:
                process.stdin.write('c\n')
                process.stdin.flush()
                self.events.put(('saving',))
        except (OSError,ValueError) as exc:
            self.events.put(('log','Could not request a checkpoint: '+str(exc)))

    def pause_save(self):
        """Quit at Hashcat's next saved restore point."""
        if not self.job_running or self.pause_requested:return
        if self.estimate_proc and self.estimate_proc.poll() is None:
            self.stop_attack()
            self.state_var.set('Estimate stopped. No password search was running.')
            return
        self.pause_requested=True
        self.pause_btn.configure(state='disabled')
        self.state_var.set('Saving at the next checkpoint…')
        if self.hashcat_proc:self._request_checkpoint(self.hashcat_proc)
        elif self.job_running:
            # Preparation has not tried candidates yet. The worker will send
            # the checkpoint request as soon as Hashcat starts.
            self.state_var.set('Preparing, then saving a checkpoint…')

    def discover_saved_session(self):
        metadata=load_saved()
        if not metadata:return
        restore=Path(metadata['restore_file'])
        if not restore.is_file() or restore.stat().st_size==0:return
        self.saved_session=metadata
        self.active_target=dict(metadata.get('target') or {})
        self.active_options=metadata.get('attack_options')
        self.session_manifest=metadata['manifest_path']
        self.ready_hash=metadata.get('hashfile')
        self.ready_target_bssid=re.sub(r'[^0-9a-fA-F]','',(metadata.get('target') or {}).get('bssid','')).lower() or None
        self.run_dir=metadata.get('run_dir')
        self.result_path=Path(metadata.get('result_path',''))
        self.capture_path.set(metadata.get('capture_path',''))
        target=metadata.get('target')
        if isinstance(target,dict) and target.get('bssid'):
            self.app.selected_target=target
            self.target_var.set('Selected: '+target.get('essid','Saved network')+' · '+target['bssid'])
        if process_active(metadata):
            self.state_var.set('This search is still running in another AirWatch window.')
            self.resume_btn.configure(state='disabled')
        else:
            self.state_var.set('Old search saved. Continue it or start a new pattern.')
            self.analysis_var.set('Saved checkpoint found for '+str(target.get('essid','this network') if isinstance(target,dict) else 'this network')+'.')
            self.resume_btn.configure(state='normal')
        self.app.navigate('Recovery')

    def open_saved_session(self):
        path=filedialog.askopenfilename(initialdir=self.app.outdir.get(),
                title='Open a saved AirWatch search',filetypes=[('AirWatch session','airwatch-session.json'),('JSON files','*.json')])
        if not path:return
        try:
            data=json.loads(Path(path).read_text())
            if data.get('version')!=1 or not Path(data['restore_file']).is_file():
                raise ValueError('This folder has no usable Hashcat checkpoint.')
            remember(path)
            self.discover_saved_session()
        except (OSError,ValueError,KeyError) as exc:
            messagebox.showerror('AirWatch','Could not open saved search: '+str(exc))

    def resume_saved(self):
        if self.job_running or not HASHCAT:return
        metadata=self.saved_session or load_saved()
        if not metadata:return
        restore=Path(metadata['restore_file'])
        hashfile=Path(metadata.get('hashfile',''))
        if process_active(metadata):
            self.state_var.set('This search is already running in another window.')
            return
        if not restore.is_file() or restore.stat().st_size==0 or not hashfile.is_file():
            self.state_var.set('Saved checkpoint or capture hash is missing.')
            self.resume_btn.configure(state='disabled')
            return
        if metadata.get('wordlist_path') and not Path(metadata['wordlist_path']).is_file():
            self.state_var.set('The saved wordlist is missing. Restore it to its original path to resume.')
            return
        if metadata.get('mask_file_path') and not Path(metadata['mask_file_path']).is_file():
            self.state_var.set('The saved state mask file is missing. Restore it to resume.')
            return
        self.saved_session=metadata
        self.active_target=dict(metadata.get('target') or {})
        self.active_options=metadata.get('attack_options')
        self.session_manifest=metadata['manifest_path']
        self.ready_hash=str(hashfile)
        self.run_dir=metadata.get('run_dir')
        self.result_path=Path(metadata['result_path'])
        self.job_running=True
        self.cancel_requested=False
        self.pause_requested=False
        self.app.emergency_active=False
        self.job_started=time.monotonic()
        self.recovered_plain=None
        self.result_var.set('No passphrase recovered yet.')
        self.reveal_btn.configure(state='disabled',text='Reveal')
        self.progress.configure(value=0)
        self.progress_var.set('0%')
        self.current_guess_var.set('Waiting for Hashcat…')
        self.tried_var.set('—')
        self.total_var.set('—')
        self.state_var.set('Resuming saved search…')
        self.start_btn.configure(state='disabled')
        self.resume_btn.configure(state='disabled')
        self.pause_btn.configure(state='normal')
        self.stop_btn.configure(state='normal')
        args=[HASHCAT,'--session',metadata['session'],'--restore',
              '--restore-file-path',str(restore)]
        def worker():
            try:self._run_hashcat(args)
            except Exception as exc:
                self.hashcat_proc=None
                self.events.put(('attack_error',str(exc)))
        threading.Thread(target=worker,daemon=True).start()

    def stop_attack(self):
        self.cancel_requested=True
        process=self.hashcat_proc or self.estimate_proc
        if process and process.poll() is None:
            self.state_var.set("Stopping Hashcat…")
            try:os.killpg(process.pid,signal.SIGINT)
            except ProcessLookupError:pass
            def ensure_stopped():
                for sig in (signal.SIGTERM,signal.SIGKILL):
                    try:process.wait(timeout=5);return
                    except subprocess.TimeoutExpired:
                        try:os.killpg(process.pid,sig)
                        except ProcessLookupError:return
            threading.Thread(target=ensure_stopped,daemon=True).start()
        elif self.job_running:
            self.cancel_requested=True
            self.state_var.set("Cancelling preparation…")

    def toggle_reveal(self):
        if not self.recovered_plain:return
        if self.reveal_btn.cget("text")=="Reveal":
            self.result_var.set("Recovered passphrase: "+self.recovered_plain)
            self.reveal_btn.configure(text="Hide")
        else:
            self.result_var.set("Passphrase recovered. Click Reveal to view it.")
            self.reveal_btn.configure(text="Reveal")

    def _sample_mask_guess(self, status):
        """Show one real candidate near the saved base position, without GPU work."""
        if self.sample_inflight or time.monotonic()-self.last_sample_at<6:
            return
        guess=status.get('guess') or {}
        mask=guess.get('guess_base')
        point=status.get('restore_point')
        options=self.active_options
        if not options:
            # Legacy checkpoints did not record the mask. Only use visible
            # settings when they exactly match the running mask's shape.
            try:options=self._attack_options()
            except ValueError:return
        if not (isinstance(mask,str) and isinstance(point,int) and 0<=point<10**16):
            return
        valid_state_masks=()
        if options.get('mode')=='state_phone':
            valid_state_masks=options.get('masks') or state_phone_masks(options.get('codes',()),'Digits only')
        if options.get('mode')=='state_phone' and mask in valid_state_masks:
            charset_flag=None
        elif options.get('mode')=='phone' and mask==PHONE_MASK:
            charset_flag='-2'
        elif options.get('mode')=='mask' and re.fullmatch(r'(?:\?1)+',mask):
            charset_flag='-1'
        else:return
        charset=options.get('charset')
        if charset_flag and not charset:return
        if not HASHCAT:return
        self.sample_inflight=True
        self.last_sample_at=time.monotonic()
        def worker():
            candidate=None
            process=None
            try:
                cache_key=(charset_flag,charset,mask)
                keyspaces=self.sample_keyspaces.get(cache_key)
                if not keyspaces:
                    def base_size(hash_mode):
                        args=[HASHCAT,'--keyspace','-a','3']
                        if hash_mode:args[2:2]=['-m',hash_mode]
                        if charset_flag:args += [charset_flag,charset]
                        args.append(mask)
                        result=subprocess.run(args,capture_output=True,text=True,timeout=4)
                        if result.returncode:raise ValueError('Could not read mask keyspace')
                        return int(result.stdout.strip())
                    keyspaces=(base_size('22000'),base_size(None))
                    self.sample_keyspaces[cache_key]=keyspaces
                target_base,stdout_base=keyspaces
                if not target_base or not stdout_base:raise ValueError('Empty mask keyspace')
                sample_point=min(stdout_base-1,point*stdout_base//target_base)
                args=[HASHCAT,'--stdout','-a','3','--skip',str(sample_point),'--limit','1']
                if charset_flag:args += [charset_flag,charset]
                args.append(mask)
                process=subprocess.Popen(args,
                                         stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                         start_new_session=True)
                if select.select([process.stdout],[],[],4)[0]:
                    raw=process.stdout.readline(256)
                    if raw:candidate=raw.decode('utf-8','replace').strip()
            except (OSError,ValueError):
                pass
            finally:
                if process:
                    try:process.terminate();process.wait(timeout=1)
                    except (OSError,subprocess.TimeoutExpired):
                        try:process.kill();process.wait(timeout=1)
                        except (OSError,subprocess.TimeoutExpired):pass
                self.events.put(('sample',candidate))
        threading.Thread(target=worker,daemon=True).start()

    def _pump(self):
        try:
            while True:
                event=self.events.get_nowait()
                kind=event[0]
                if kind=="devices":
                    self.devices=event[1]
                    self.device_combo.configure(values=[d.label for d in self.devices])
                    chosen=preferred_device(self.devices)
                    self.device_var.set(chosen.label if chosen else "Select a GPU explicitly")
                    self.gpu_status.set("Default selected: "+chosen.name if chosen else "GeForce was not detected. Choose another available GPU explicitly, or check the NVIDIA runtime.")
                    self.refresh_gpu_btn.state(["!disabled"])
                elif kind=="device_error":
                    self.gpu_status.set(event[1]);self.refresh_gpu_btn.state(["!disabled"])
                elif kind=="install":
                    self.refresh_tools()
                    if event[1]:self._log("hcxtools installation failed: "+event[2])
                    else:self._log("hcxtools installed. Analyze the capture again.")
                elif kind=="analysis":
                    current=self.app.selected_target or {}
                    current_bssid=re.sub(r"[^0-9a-fA-F]","",current.get("bssid","")).lower()
                    if current_bssid!=event[5] or str(Path(self.capture_path.get()).expanduser())!=event[6]:
                        self.ready_hash=None;self.analyze_btn.configure(state="normal")
                        self.analysis_var.set("Selection changed during analysis. Analyze the current target and capture again.")
                        continue
                    self.ready_hash=event[1];self.run_dir=event[2]
                    self.ready_target_bssid=event[5]
                    self.active_target=dict(self.app.selected_target or {})
                    self.analysis_var.set(f"Ready: {event[3]} EAPOL record(s), {event[4]} PMKID record(s) for selected AP.")
                    self.analyze_btn.configure(state="normal")
                    self._log("Selected target hash saved: "+event[1])
                    self.app.update_workflow(stage=5,note="Handshake data is ready. Choose wordlist or mask, then start Hashcat.")
                    if getattr(self.app,'_active_tab',None)=='Capture':self.app.navigate('Recovery')
                elif kind=="analysis_error":
                    self.analysis_var.set(event[1])
                    self.analyze_btn.configure(state="normal")
                    self._log("Capture analysis: "+event[1])
                elif kind=="estimate":
                    self.job_running=False;self.start_btn.state(["!disabled"]);self.stop_btn.state(["disabled"]);self.state_var.set("Estimate ready")
                    speed,total=event[1],event[2]
                    limit=int(self.runtime.get())
                    limit_note=f" Stops after {limit} second{'s' if limit!=1 else ''}." if limit else ""
                    self.estimate_var.set(f"Approx. {duration(total/speed)} at {compact_number(speed)} guesses/s.{limit_note}")
                    self.estimate_btn.configure(state="normal")
                elif kind=="estimate_error":
                    self.estimate_proc=None;self.job_running=False;self.start_btn.state(["!disabled"]);self.stop_btn.state(["disabled"]);self.state_var.set("Estimate stopped")
                    self.estimate_var.set(event[1])
                    self.estimate_btn.configure(state="normal")
                elif kind=="prepare":
                    self.state_var.set(f"Preparing compressed wordlist… {event[1]}%")
                    self.progress.configure(value=event[1])
                    self.progress_var.set(f"{event[1]}%")
                elif kind=="hashcat_start":
                    self.progress.configure(value=0)
                    self.progress_var.set("0%")
                    self.state_var.set("Hashcat starting…")
                    self.pause_btn.configure(state='disabled' if self.pause_requested else 'normal')
                elif kind=='saving':
                    self.state_var.set('Saving at the next checkpoint…')
                    self.pause_btn.configure(state='disabled')
                elif kind=="keyspace":
                    self.keyspace_var.set("Search contains approximately "+compact_number(event[1])+" candidates. ETA will use live speed.")
                    self.total_var.set(f"{int(event[1]):,}")
                elif kind=="status":
                    data=event[1]
                    done,total=data.get("progress",[0,0])[:2]
                    if self.active_options and self.active_options.get('mode')=='state_phone' and total:
                        guess=data.get('guess') or {}
                        count=len(self.active_options.get('masks') or self.active_options.get('codes',()))
                        try:index=int(guess.get('guess_base_offset',1))
                        except (TypeError,ValueError):index=1
                        if count:
                            done=(max(1,min(count,index))-1)*total+done
                            total*=count
                    percent=100*done/total if total else 0
                    self.progress.configure(value=min(100,percent))
                    self.progress_var.set(f"{percent:.1f}%")
                    speed=sum(max(0,int(device.get("speed",0))) for device in data.get("devices",[]))
                    self.speed_var.set("Speed: "+compact_number(speed)+" guesses/s")
                    eta=int(data.get("estimated_stop",0))
                    if self.active_options and self.active_options.get('mode')=='state_phone':
                        remaining=(total-done)/speed if speed else None
                    else:
                        remaining=max(0,eta-time.time()) if eta>time.time() else ((total-done)/speed if speed else None)
                    self.eta_var.set("ETA: "+duration(remaining))
                    states={3:"Running",4:"Paused",5:"Exhausted",6:"Recovered",7:"Aborted",8:"Stopped",10:"Saving checkpoint"}
                    self.state_var.set('Saving at the next checkpoint…' if self.pause_requested else states.get(data.get("status"),"Running"))
                    self.tried_var.set(f"{int(done):,}")
                    self.total_var.set(f"{int(total):,}" if total else "—")
                    candidates=next((device.get('candidates') or device.get('guess_candidates')
                                     for device in data.get('devices',[])
                                     if device.get('candidates') or device.get('guess_candidates')),None)
                    if candidates:
                        if isinstance(candidates,(list,tuple)):
                            candidates=' → '.join(str(item) for item in candidates)
                        self.current_guess_var.set(str(candidates))
                    else:
                        pattern=(data.get('guess') or {}).get('guess_base')
                        if not self.current_guess_var.get().startswith('Near now:'):
                            self.current_guess_var.set('Pattern: '+str(pattern) if pattern else 'Live guess unavailable')
                        if data.get('status')==3 and not self.pause_requested:
                            self._sample_mask_guess(data)
                elif kind=='sample':
                    self.sample_inflight=False
                    if event[1] and self.job_running:
                        self.current_guess_var.set('Near now: '+event[1])
                elif kind=="log":
                    self._log(event[1])
                elif kind=="done":
                    self.job_running=False
                    self.stop_btn.configure(state='disabled')
                    self.pause_btn.configure(state='disabled')
                    self.start_btn.configure(state='normal')
                    restore_file=None
                    if self.session_manifest:
                        try:restore_file=Path(json.loads(Path(self.session_manifest).read_text())['restore_file'])
                        except (OSError,ValueError,KeyError):pass
                    resumable=bool(restore_file and restore_file.is_file() and restore_file.stat().st_size)
                    if self.result_path and self.result_path.is_file() and self.result_path.stat().st_size:
                        if self.session_manifest:clear_if_current(self.session_manifest)
                        self.saved_session=None
                        self.resume_btn.configure(state='disabled')
                        self.recovered_plain=self.result_path.read_text(errors="replace").splitlines()[0]
                        self.result_var.set("Passphrase recovered. Click Reveal to view it.")
                        self.reveal_btn.configure(state="normal")
                        self.state_var.set("Recovered")
                        self.app.update_workflow(stage=5,note="Passphrase recovered for the selected access point. Reveal it here or open the results folder.")
                    elif resumable:
                        try:
                            metadata=json.loads(Path(self.session_manifest).read_text())
                            metadata.update(pid=0,status='saved')
                            write_manifest(self.session_manifest,metadata)
                        except (OSError,ValueError):pass
                        self.saved_session=load_saved()
                        self.resume_btn.configure(state='normal' if self.saved_session else 'disabled')
                        if self.saved_session and self.pause_requested:
                            self.state_var.set('Paused and saved. You can close AirWatch.')
                        elif self.saved_session and self.saved_session.get('runtime_limit'):
                            self.state_var.set('Time limit reached. Search saved. Set Stop after to 0 for a new search without a limit.')
                        else:
                            self.state_var.set('Search stopped. Checkpoint saved in results folder.')
                        self.app.update_workflow(stage=5,note='Search checkpoint saved. Resume later without starting over.')
                    elif event[1]==1:
                        if self.session_manifest:clear_if_current(self.session_manifest)
                        self.saved_session=None
                        self.resume_btn.configure(state='disabled')
                        self.state_var.set("Search exhausted. No match in this search space.")
                        self.app.update_workflow(stage=5,note="This search was exhausted. Try a focused custom list or a narrower mask based on what you know.")
                    elif event[1]==0:
                        if self.session_manifest:clear_if_current(self.session_manifest)
                        self.saved_session=None
                        self.resume_btn.configure(state='disabled')
                        self.state_var.set("Finished. Review results in the recovery folder.")
                        self.app.update_workflow(stage=5,note="Search finished. Review the recovery folder for output.")
                    else:
                        self.state_var.set(f"Hashcat stopped (exit {event[1]}). See log below.")
                        self.app.update_workflow(stage=5,note="Hashcat stopped. Review its log, then adjust the search if needed.")
                    self.pause_requested=False
                elif kind=="attack_error":
                    self.job_running=False;self.stop_btn.configure(state="disabled");self.pause_btn.configure(state='disabled');self.start_btn.configure(state="normal")
                    self.state_var.set("Could not start Hashcat." if event[1]!="Preparation cancelled." else "Preparation cancelled.")
                    self._log(event[1])
                    self.pause_requested=False
                    self.discover_saved_session()
        except queue.Empty:pass
        if self.job_running and self.job_started:
            self.elapsed_var.set("Elapsed: "+duration(time.monotonic()-self.job_started).replace("about ",""))
        self.after(250,self._pump)
