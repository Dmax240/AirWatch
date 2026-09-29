"""Evidence and optional AI advice within the AirWatch workflow."""
import json
import queue
import threading
import time
import struct
import tempfile
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from handshake_assistant.engine import Analyzer, coach
from handshake_assistant.capture import CaptureRunner, read_capture
from handshake_assistant.ai import api_key
from live_advice import cloud_input


class CoachPanel(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent,padding=18)
        self.app=app;self.events=queue.Queue();self.snapshot=None
        self.snapshot_identity=None
        self.busy=False;self.ai_busy=False;self.runner=None;self.last_live=0
        self.source=tk.StringVar();self.target=tk.StringVar()
        self.status=tk.StringVar(value='Select an access point and capture, or open a saved capture.')
        self.live=tk.BooleanVar(value=True)
        ttk.Label(self,text='Understand the capture',style='Title.TLabel').pack(anchor='w')
        ttk.Label(self,text='Observed message structure and local guidance · optional AI interpretation',style='Sub.TLabel').pack(anchor='w',pady=(4,12))
        row=ttk.Frame(self);row.pack(fill='x')
        ttk.Entry(row,textvariable=self.source).pack(side='left',fill='x',expand=True)
        ttk.Button(row,text='Open capture…',command=self.browse).pack(side='left',padx=6)
        ttk.Button(row,text='Use current capture',command=self.use_current).pack(side='left')
        row=ttk.Frame(self);row.pack(fill='x',pady=8)
        ttk.Label(row,text='BSSID filter (optional)').pack(side='left')
        ttk.Entry(row,textvariable=self.target,width=24).pack(side='left',padx=8)
        self.analyze_btn=ttk.Button(row,text='Analyze evidence',command=self.analyze);self.analyze_btn.pack(side='left')
        ttk.Checkbutton(row,text='Update during focused capture',variable=self.live).pack(side='left',padx=12)
        ttk.Label(self,textvariable=self.status,wraplength=1100).pack(fill='x',pady=8)
        self.metrics=ttk.Label(self,text='Frames —    EAPOL —    Consistent exchanges —',style='CardHead.TLabel');self.metrics.pack(anchor='w',pady=8)
        self.table=ttk.Treeview(self,columns=('id','observed','missing','consistent','frames'),show='headings',height=5)
        for col,label,width in [('id','Exchange',80),('observed','Observed',150),('missing','Missing',150),('consistent','Consistent M1–M4',160),('frames','Packet numbers',320)]:
            self.table.heading(col,text=label);self.table.column(col,width=width)
        self.table.pack(fill='both',expand=True)
        ttk.Label(self,text='A consistent exchange is not password recovery or cryptographic MIC verification.',style='Sub.TLabel').pack(anchor='w',pady=6)
        actions=ttk.Frame(self);actions.pack(fill='x',pady=8)
        self.ai_btn=ttk.Button(actions,text='Ask AI about this evidence',command=self.ask_ai);self.ai_btn.pack(side='left')
        ttk.Button(actions,text='Preview data sent to AI',command=self.preview).pack(side='left',padx=8)
        ttk.Button(actions,text='Export evidence',command=self.export).pack(side='left')
        ttk.Label(actions,text='AI configured' if api_key() else 'AI key unavailable',style='Sub.TLabel').pack(side='right')
        ttk.Label(self,text='AI sends only allow-listed statistics and message numbers to OpenAI. No SSIDs, MAC addresses, nonces, MICs, passwords, or packet payloads.',wraplength=1100,style='Sub.TLabel').pack(fill='x')
        self.notes=tk.Text(self,height=9,wrap='word',font=('TkDefaultFont',10),padx=12,pady=12,state='disabled')
        self.notes.pack(fill='both',expand=True,pady=(8,0))
        self.after(200,self.pump)

    def show(self,text):
        self.notes.configure(state='normal');self.notes.delete('1.0','end');self.notes.insert('end',text);self.notes.configure(state='disabled')

    def current_snapshot(self):
        """Return only evidence actually analyzed for the selected capture and AP."""
        source=self.app.capture_prefix+'-01.cap' if self.app.capture_prefix else ''
        target=(self.app.selected_target or {}).get('bssid','').lower()
        if (self.snapshot and self.snapshot_identity==(source,target) and
            self.source.get()==source and self.snapshot.get('target','').lower()==target):
            return self.snapshot
        return None

    def browse(self):
        path=filedialog.askopenfilename(filetypes=[('Packet captures','*.cap *.pcap *.pcapng')])
        if path:self.source.set(path);self.analyze()

    def use_current(self):
        if self.app.capture_prefix:self.source.set(self.app.capture_prefix+'-01.cap')
        if self.app.selected_target:self.target.set(self.app.selected_target['bssid'])
        self.analyze()

    def maybe_live(self):
        if self.app.emergency_active:return
        if self.live.get() and not self.busy and self.app.capture_focused and time.monotonic()-self.last_live>15:
            self.last_live=time.monotonic()
            path=Path(self.app.capture_prefix+'-01.cap')
            if path.exists() and 24<path.stat().st_size<16*1024*1024:
                self.source.set(str(path));self.target.set(self.app.selected_target['bssid']);self.analyze(live=True)
            elif path.exists() and path.stat().st_size>=16*1024*1024:
                self.status.set('Live analysis paused at 16 MiB to limit load. Stop capture, then Analyze evidence for the full file.')

    def analyze(self,live=False):
        if self.busy:return
        path=self.source.get();target=self.target.get().strip().lower()
        if not Path(path).is_file():self.status.set('Choose an existing packet capture.');return
        try:analyzer=Analyzer(target)
        except ValueError as e:self.status.set(str(e));return
        if not live or self.snapshot_identity!=(path,target):self.snapshot=None
        self.busy=True;self.analyze_btn.state(['disabled']);self.status.set('Updating packet evidence…' if live and self.snapshot else 'Reading packet evidence…')
        runner=CaptureRunner();self.runner=runner
        def worker():
            timer=threading.Timer(45,runner.stop);timer.daemon=True;timer.start()
            snapshot_path=None
            try:
                input_path=path
                if live:
                    # A growing pcap may end midway through a packet. Snapshot
                    # complete records only, bounded to 16 MiB.
                    with open(path,'rb') as stream:data=stream.read(16*1024*1024)
                    magic=data[:4]
                    endian='<' if magic in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'
                    if magic not in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\xa1\xb2\x3c\x4d'):raise RuntimeError('Live preview requires a pcap capture.')
                    end=24
                    while end+16<=len(data):
                        length=struct.unpack_from(endian+'I',data,end+8)[0]
                        if end+16+length>len(data):break
                        end+=16+length
                    with tempfile.NamedTemporaryFile(suffix='.pcap',delete=False) as temp:
                        temp.write(data[:end]);snapshot_path=temp.name
                    input_path=snapshot_path
                read_capture(input_path,analyzer.ingest,runner)
                if runner.stopped.is_set():raise RuntimeError('Analysis cancelled or reached its 45-second limit. Use a smaller capture.')
                self.events.put(('evidence',analyzer.snapshot(),path,target))
            except Exception as e:self.events.put(('error',str(e)))
            finally:
                timer.cancel()
                if snapshot_path:Path(snapshot_path).unlink(missing_ok=True)
        threading.Thread(target=worker,daemon=True).start()

    def ask_ai(self):
        advisor=self.app.live_advisor
        if advisor.busy:return
        self.app.emergency_active=False
        snapshot,context,signature=advisor.evidence()
        self.status.set('Astra High is reviewing the best next step. Watch the pinned advice card.')
        advisor.launch(snapshot,context,signature)

    def preview(self):
        snapshot,context,_=self.app.live_advisor.evidence()
        self.app.details_dialog('AI data preview','This is the anonymized evidence and operation state used by automatic Astra High reviews and Ask AI. Identifiers, raw packets and passwords are excluded.',json.dumps(cloud_input(snapshot,context),indent=2))

    def export(self):
        if not self.snapshot:return
        path=filedialog.asksaveasfilename(defaultextension='.json',initialfile='capture-evidence.json')
        if path:Path(path).write_text(json.dumps(self.snapshot,indent=2))

    def pump(self):
        try:
            for _ in range(20):
                event=self.events.get_nowait();kind=event[0]
                if kind=='evidence':
                    self.busy=False;self.analyze_btn.state(['!disabled'])
                    if self.source.get()!=event[2] or self.target.get().strip().lower()!=event[3]:
                        self.snapshot=None;self.status.set('Selection changed during analysis. Analyze the current capture again.')
                        continue
                    self.snapshot=event[1]
                    self.snapshot_identity=(event[2],event[3])
                    s=self.snapshot
                    self.metrics.configure(text=f"Frames {s['frames_observed']:,}    EAPOL {s['eapol_frames']:,}    Consistent exchanges {s['consistent_exchanges']}")
                    self.table.delete(*self.table.get_children())
                    for e in s['exchanges'][-100:]:
                        self.table.insert('','end',values=(e['id'],', '.join('M'+str(n) for n in e['observed']),', '.join('M'+str(n) for n in e['missing']) or 'None','Yes' if e['consistent_four_messages'] else 'No',str(e['frames'])))
                    self.show('LOCAL FINDINGS\n\n'+'\n\n'.join(coach(s)))
                    self.status.set('Evidence updated · '+Path(event[2]).name)
                elif kind=='error':
                    self.busy=False;self.analyze_btn.state(['!disabled']);self.status.set(event[1])
                elif kind in ('ai','ai_error'):
                    self.ai_busy=False;self.ai_btn.state(['!disabled'])
                    if kind=='ai':
                        self.show('AI INTERPRETATION\n\n'+event[1])
                        stale=self.snapshot!=event[2]
                        self.status.set('Advice describes an earlier evidence snapshot; request updated advice for the latest capture.' if stale else 'AI advice received. Check suggestions against the packet evidence.')
                    else:self.status.set(event[1])
        except queue.Empty:pass
        self.after(200,self.pump)

    def close(self):
        if self.runner:threading.Thread(target=self.runner.stop,daemon=True).start()
