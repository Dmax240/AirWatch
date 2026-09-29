"""Task-first AirWatch interface; detailed panels stay available under Advanced."""
import os
import queue
import subprocess
import tempfile
import threading
import shutil
import time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from preferences import load as load_preferences, save as save_preferences
from reconnect_panel import ReconnectPanel


def channel_band(channel):
    try:number=int(channel)
    except (TypeError,ValueError):return 'Unknown band'
    if 1 <= number <= 14:return '2.4 GHz'
    if 32 <= number <= 177:return '5 GHz'
    return 'Other band'


class GuidedView(ttk.Frame):
    def __init__(self, app):
        super().__init__(app, padding=14)
        self.app=app
        self.recovery=app.recovery_panel
        self.notice=''
        self.rows=()
        self.network_filter=tk.StringVar()
        self.picking=False
        self.visible_section=None
        self.title_var=tk.StringVar()
        self.detail_var=tk.StringVar()
        self.context_var=tk.StringVar()
        self.action_var=tk.StringVar()
        self.gpu_var=tk.StringVar()
        settings=load_preferences()
        for key,value in settings.items():
            variable=getattr(self.recovery,key,None)
            if isinstance(variable,tk.Variable):variable.set(value)
        exact_ten=(self.recovery.method.get()=='mask' and self.recovery.digits.get() and not any(v.get() for v in (self.recovery.lower,self.recovery.upper,self.recovery.symbols)) and self.recovery.min_len.get()==self.recovery.max_len.get()==10)
        initial='Wordlist' if self.recovery.method.get()=='wordlist' else '10-digit number' if exact_ten else 'Custom pattern'
        self.pattern=tk.StringVar(value=initial)
        self.auto_stop_requested_for=None
        self.events=queue.Queue();self.probing=False;self.probe_at=0;self.ready_prefix=None
        self._style()
        self._build()
        self.show()
        self.after(150,self.refresh)

    def _style(self):
        s=ttk.Style(self)
        s.configure('Guide.Title.TLabel',font=('TkDefaultFont',20,'bold'),background='#f4f6f8',foreground='#25305a')
        s.configure('Guide.Hero.TLabel',font=('TkDefaultFont',16,'bold'),background='white',foreground='#25305a')
        s.configure('Guide.Primary.TButton',font=('TkDefaultFont',11,'bold'),padding=(16,10),background='#6c63e8',foreground='white',borderwidth=0)
        s.map('Guide.Primary.TButton',background=[('disabled','#cbd5e1'),('active','#5147c4')],foreground=[('disabled','#475467')])
        s.configure('Guide.Secondary.TButton',padding=(12,9))
        s.configure('Guide.Step.TLabel',padding=(10,6),font=('TkDefaultFont',11,'bold'),background='#e9edf3',foreground='#667085')
        s.configure('Guide.Active.TLabel',padding=(10,6),font=('TkDefaultFont',11,'bold'),background='#e5efff',foreground='#175cd3')
        s.configure('Guide.Done.TLabel',padding=(10,6),font=('TkDefaultFont',11,'bold'),background='#e8f6ee',foreground='#067647')

    def _build(self):
        head=ttk.Frame(self);head.pack(fill='x')
        ttk.Label(head,text='AirWatch ✦',style='Guide.Title.TLabel').pack(side='left')
        self.advanced_btn=ttk.Button(head,text='More options',command=lambda:self.app.navigate('Adapters'),style='Guide.Secondary.TButton');self.advanced_btn.pack(side='right')
        self.back_btn=ttk.Button(head,text='← Choose another network',command=self.back_to_network,style='Guide.Secondary.TButton')
        hero=ttk.Frame(self,style='Card.TFrame',padding=12);hero.pack(fill='x',pady=(8,8))
        self.primary=ttk.Button(hero,textvariable=self.action_var,command=self.act,style='Guide.Primary.TButton')
        self.primary.pack(side='right',padx=(20,0))
        text=ttk.Frame(hero,style='Card.TFrame');text.pack(side='left',fill='x',expand=True)
        ttk.Label(text,textvariable=self.context_var,style='Card.TLabel').pack(anchor='w')
        ttk.Label(text,textvariable=self.title_var,style='Guide.Hero.TLabel',wraplength=780).pack(anchor='w',pady=(7,6))
        self.detail=ttk.Label(text,textvariable=self.detail_var,style='Card.TLabel',wraplength=780,justify='left')
        self.detail.pack(anchor='w')
        text.bind('<Configure>',lambda e:self.detail.configure(wraplength=max(250,e.width)))
        self.body_shell=ttk.Frame(self);self.body_shell.pack(fill='both',expand=True)
        self.canvas=tk.Canvas(self.body_shell,highlightthickness=0,background='#f4f6f8')
        scroll=ttk.Scrollbar(self.body_shell,orient='vertical',command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y');self.canvas.pack(side='left',fill='both',expand=True)
        self.body=ttk.Frame(self.canvas)
        window=self.canvas.create_window((0,0),window=self.body,anchor='nw')
        self.body.bind('<Configure>',lambda _e:self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>',lambda e:self.canvas.itemconfigure(window,width=e.width))
        for event in ('<MouseWheel>','<Button-4>','<Button-5>'):self.bind_all(event,self.wheel,add='+')
        self.network=ttk.Frame(self.body,style='Card.TFrame',padding=18)
        bar=ttk.Frame(self.network,style='Card.TFrame');bar.pack(fill='x',pady=(0,10))
        ttk.Label(bar,text='Nearby Wi-Fi',style='CardHead.TLabel').pack(side='left')
        self.scan_stop=ttk.Button(bar,text='■ Stop scan',command=app_stop(self.app));self.scan_stop.pack(side='right')
        search_row=ttk.Frame(self.network,style='Card.TFrame');search_row.pack(fill='x',pady=(0,10))
        ttk.Label(search_row,text='Search',style='Card.TLabel').pack(side='left',padx=(0,10))
        self.search_entry=ttk.Entry(search_row,textvariable=self.network_filter)
        self.search_entry.pack(side='left',fill='x',expand=True)
        ttk.Button(search_row,text='✕',command=lambda:self.network_filter.set('')).pack(side='left',padx=(8,0))
        self.network_list=ttk.Frame(self.network,style='Card.TFrame');self.network_list.pack(fill='both',expand=True)
        self.networks=ttk.Treeview(self.network_list,columns=('name','security','band','signal','channel'),show='headings',selectmode='browse',height=8)
        for c,label,width in [('name','Name',360),('security','Security',160),('band','Band',110),('signal','Signal',130),('channel','Channel',85)]:
            self.networks.heading(c,text=label);self.networks.column(c,width=width,anchor='w')
        self.network_scroll=ttk.Scrollbar(self.network_list,orient='vertical',command=self.networks.yview)
        self.networks.configure(yscrollcommand=self.network_scroll.set)
        self.network_scroll.pack(side='right',fill='y');self.networks.pack(side='left',fill='both',expand=True)
        self.networks.bind('<<TreeviewSelect>>',self.pick_network)
        self.empty=ttk.Label(self.network,text='Tap Find networks to see nearby WPA2 networks.',style='Card.TLabel',wraplength=1000)
        self.empty.pack(anchor='w',pady=(12,0))
        self.capture=ttk.Frame(self.body,style='Card.TFrame',padding=20)
        ttk.Label(self.capture,text='Capture',style='CardHead.TLabel').pack(anchor='w',pady=(0,10))
        self.capture_metrics=ttk.Label(self.capture,text='Waiting for packet evidence…',style='Card.TLabel',font=('TkDefaultFont',15))
        self.capture_metrics.pack(anchor='w',pady=(18,14))
        self.reconnect_open=False
        self.reconnect_toggle=ttk.Button(self.capture,text='Show reconnect controls',command=self.toggle_reconnect)
        self.reconnect_toggle.pack(anchor='w',pady=(0,10))
        self.reconnect_host=ttk.Frame(self.capture,style='Card.TFrame')
        self.reconnect_panel=ReconnectPanel(self.reconnect_host,self.app)
        self.reconnect_panel.pack(fill='x')
        self.recover=ttk.Frame(self.body,style='Card.TFrame',padding=20)
        ttk.Label(self.recover,text='Try a password search',style='CardHead.TLabel').pack(anchor='w')
        row=ttk.Frame(self.recover,style='Card.TFrame');row.pack(fill='x',pady=(12,8))
        self.pattern_box=ttk.Combobox(row,textvariable=self.pattern,values=('10-digit number','Wordlist','Custom pattern'),state='readonly',width=22)
        self.pattern_box.pack(side='left');self.pattern_box.bind('<<ComboboxSelected>>',self.choose_pattern)
        self.pattern_help=ttk.Label(row,text='',style='Card.TLabel');self.pattern_help.pack(side='left',padx=14)
        self.word_row=ttk.Frame(self.recover,style='Card.TFrame')
        ttk.Entry(self.word_row,textvariable=self.recovery.wordlist_path).pack(side='left',fill='x',expand=True)
        ttk.Button(self.word_row,text='Choose wordlist…',command=self.recovery.browse_wordlist).pack(side='left',padx=(8,0))
        self.custom_row=ttk.Frame(self.recover,style='Card.TFrame')
        for label,var in [('a–z',self.recovery.lower),('A–Z',self.recovery.upper),('0–9',self.recovery.digits),('Symbols',self.recovery.symbols)]:
            ttk.Checkbutton(self.custom_row,text=label,variable=var,command=self.recovery.update_estimate).pack(side='left',padx=(0,12))
        ttk.Label(self.custom_row,text='Length',style='Card.TLabel').pack(side='left',padx=(12,6))
        ttk.Spinbox(self.custom_row,from_=8,to=63,width=4,textvariable=self.recovery.min_len).pack(side='left')
        ttk.Label(self.custom_row,text='to',style='Card.TLabel').pack(side='left',padx=6)
        ttk.Spinbox(self.custom_row,from_=8,to=63,width=4,textvariable=self.recovery.max_len).pack(side='left')
        self.gpu_row=ttk.Frame(self.recover,style='Card.TFrame');self.gpu_row.pack(fill='x',pady=(12,8))
        ttk.Label(self.gpu_row,text='GPU',style='Card.TLabel').pack(side='left',padx=(0,8))
        self.gpu=ttk.Combobox(self.gpu_row,textvariable=self.gpu_var,state='readonly',width=42);self.gpu.pack(side='left')
        self.gpu.bind('<<ComboboxSelected>>',self.choose_gpu)
        ttk.Checkbutton(self.gpu_row,text='High performance (-w 3)',variable=self.recovery.fast_workload,command=self.recovery.update_estimate).pack(side='left',padx=15)
        estimate=ttk.Frame(self.recover,style='Card.TFrame');estimate.pack(fill='x',pady=(0,10))
        self.estimate_btn=ttk.Button(estimate,text='Estimate time',command=self.recovery.estimate_time);self.estimate_btn.pack(side='left')
        ttk.Label(estimate,textvariable=self.recovery.estimate_var,style='Card.TLabel',wraplength=850).pack(side='left',padx=12)
        ttk.Separator(self.recover).pack(fill='x',pady=8)
        ttk.Label(self.recover,textvariable=self.recovery.state_var,style='CardHead.TLabel').pack(anchor='w',pady=(8,6))
        self.progress=ttk.Progressbar(self.recover,maximum=100);self.progress.pack(fill='x',pady=(0,8))
        stats=ttk.Frame(self.recover,style='Card.TFrame');stats.pack(fill='x')
        for var in (self.recovery.progress_var,self.recovery.speed_var,self.recovery.eta_var):
            ttk.Label(stats,textvariable=var,style='Card.TLabel').pack(side='left',padx=(0,24))
        result=ttk.Frame(self.recover,style='Card.TFrame');result.pack(fill='x',pady=(16,0))
        ttk.Label(result,textvariable=self.recovery.result_var,style='Card.TLabel').pack(side='left')
        self.reveal=ttk.Button(result,text='Reveal password',command=self.recovery.toggle_reveal);self.reveal.pack(side='left',padx=12)
        self.body_shell.pack_forget();self.body_shell.pack(fill='both',expand=True)
        self.choose_pattern()

    def toggle_reconnect(self):
        self.reconnect_open=not self.reconnect_open
        if self.reconnect_open:
            self.reconnect_host.pack(fill='x',pady=(0,12),after=self.reconnect_toggle)
            self.reconnect_toggle.configure(text='Hide reconnect controls')
        else:
            self.reconnect_host.pack_forget()
            self.reconnect_toggle.configure(text='Show reconnect controls')
    def save_settings(self):
        keys=('method','wordlist_path','lower','upper','digits','symbols','min_len','max_len','fast_workload','optimized','temperature','runtime')
        values={}
        for key in keys:
            try:values[key]=getattr(self.recovery,key).get()
            except tk.TclError:pass
        values['auto_ai']=self.app.live_advisor.enabled.get()
        try:save_preferences(values)
        except OSError as exc:self.app._log(f'Could not save preferences: {exc}')

    def wheel(self,event):
        if event.widget in (self.networks,self.network_scroll):return
        widget=event.widget;inside=False
        while widget:
            if widget is self.body_shell:inside=True;break
            widget=getattr(widget,'master',None)
        if not inside or not self.winfo_ismapped():return
        amount=-3 if getattr(event,'num',None)==4 or getattr(event,'delta',0)>0 else 3
        self.canvas.yview_scroll(amount,'units')
        return 'break'

    def show(self):
        self.app.advanced_root.pack_forget();self.pack(fill='both',expand=True)

    def show_advanced(self):
        self.pack_forget();self.app.advanced_root.pack(fill='both',expand=True)

    def set_section(self,section):
        if self.visible_section==section:return
        for frame in (self.network,self.capture,self.recover):frame.pack_forget()
        {'network':self.network,'capture':self.capture,'recovery':self.recover}[section].pack(fill='both',expand=True)
        self.visible_section=section
        self.canvas.yview_moveto(0)

    def pick_network(self,_event=None):
        if self.picking:return
        chosen=self.networks.selection()
        if not chosen or chosen[0] not in self.app.table.get_children():return
        self.app.table.selection_set(chosen[0]);self.app.select_target();self.notice=''

    def choose_pattern(self,_event=None):
        r=self.recovery;choice=self.pattern.get()
        self.word_row.pack_forget();self.custom_row.pack_forget()
        if choice=='10-digit number':
            r.method.set('mask');r.lower.set(False);r.upper.set(False);r.digits.set(True);r.symbols.set(False);r.min_len.set(10);r.max_len.set(10)
            self.pattern_help.configure(text='Exactly 10 digits, including leading zeroes.')
        elif choice=='Wordlist':
            r.method.set('wordlist');self.word_row.pack(fill='x',pady=4,before=self.gpu_row)
            self.pattern_help.configure(text='Try passwords from the file you choose.')
        else:
            r.method.set('mask');self.custom_row.pack(fill='x',pady=4,before=self.gpu_row)
            self.pattern_help.configure(text='Choose the characters and length you know.')
        r.update_estimate()

    def choose_gpu(self,_event=None):
        match=next((d for d in self.recovery.devices if d.name==self.gpu_var.get()),None)
        if match:self.recovery.device_var.set(match.label);self.recovery.update_estimate()

    def prepare_adapter(self):
        app=self.app;app.refresh_interfaces()
        current=app.interfaces.get(app.interface.get(),{})
        idle=[name for name,v in app.interfaces.items() if not v.get('ssid')]
        if current.get('ssid') and idle:
            app.interface.set(idle[0]);app.adapter_table.selection_set(idle[0]);current=app.interfaces[idle[0]]
        name=app.interface.get()
        if not name:raise RuntimeError('Connect a Wi-Fi adapter, then press Find networks again.')
        if current.get('ssid'):
            if not messagebox.askyesno('Use the connected adapter?',f'{name} is connected to {current["ssid"]}. Using it for capture will disconnect this computer. Continue?'):
                return False
        if current.get('mode')!='monitor':
            airmon=shutil.which('airmon-ng') or '/usr/sbin/airmon-ng'
            result=app._run_privileged([airmon,'start',name])
            if result.returncode:raise RuntimeError((result.stdout+result.stderr).strip()[-1200:])
            app.refresh_interfaces(prefer_mode='monitor',prefer_phy=current.get('phy'))
        if app.interfaces.get(app.interface.get(),{}).get('mode')!='monitor':
            raise RuntimeError('The adapter did not enter capture mode. Open Advanced → Adapter diagnostics.')
        return True

    def act(self):
        app=self.app;r=self.recovery
        if app.admin_busy or app.stopping or app.pending_focused:return
        self.notice=''
        try:
            if self.visible_section!='network' and not app.selected_target:
                app.navigate('Networks');return
            if (r.job_running or r.ready_hash) and self.visible_section!='recovery':
                app.navigate('Recovery');return
            if self.visible_section=='recovery' and not (r.job_running or r.ready_hash):
                app.navigate('Capture' if app.selected_target else 'Networks');return
            if r.job_running:r.pause_save();return
            if r.saved_session:r.resume_saved();return
            if app.proc and app.capture_focused:app.stop_capture();return
            if r.ready_hash:
                r.start_attack();return
            if app.selected_target:
                app.client_suitability.refresh()
                if app.proc and not app.capture_focused and app.client_suitability.complete_record_observed():
                    app.pending_scan_recovery=True;app.stop_capture();return
                if not app.client_suitability.can_capture():
                    self.notice=app.client_suitability.state()[1];return
                if app.proc:
                    app.pending_focused=True;app.stop_capture()
                    app.navigate('Capture')
                elif self.prepare_adapter():
                    app.start_capture(focused=True)
                    if app.proc:app.navigate('Capture')
            elif not app.proc and self.prepare_adapter():app.start_capture()
        except Exception as exc:self.notice=str(exc)

    def back_to_network(self):
        if self.recovery.job_running:
            self.notice='Stop the recovery search before choosing another network.';return
        if self.app.proc:
            if self.app.pending_network_return:return
            if not messagebox.askyesno('Choose another network?','Stop and save the current capture, then return to network selection?'):
                return
            self.app.pending_network_return=True
            self.app.stop_capture()
            return
        self.reset_to_network()

    def reset_to_network(self):
        self.app.selected_target=None;self.app.capture_focused=False;self.recovery.ready_hash=None
        self.app.coach_panel.snapshot=None;self.notice=''
        self.app.pending_network_return=False
        self.app.client_suitability.select(None)
        self.network_filter.set('')
        self.networks.selection_remove(*self.networks.selection())
        self.app.table.selection_remove(*self.app.table.selection())
        self.app.navigate('Networks')
        self.canvas.yview_moveto(0)

    def probe(self):
        app=self.app
        if app.emergency_active:return
        if self.probing or time.monotonic()-self.probe_at<5 or not self.recovery.converter:return
        prefix=app.capture_prefix;target=(app.selected_target or {}).get('bssid','')
        path=Path(prefix+'-01.cap')
        if not path.exists() or not 24<path.stat().st_size<=512*1024*1024:return
        self.probing=True;self.probe_at=time.monotonic()
        converter=self.recovery.converter
        def worker():
            try:
                with tempfile.TemporaryDirectory(prefix='airwatch-probe-') as folder:
                    output=Path(folder)/'check.hc22000'
                    if app.emergency_active:
                        self.events.put(('probe',prefix,target,False));return
                    subprocess.run([converter,'-o',str(output),str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
                    wanted=target.replace(':','').lower()
                    usable=False
                    if output.exists():
                        for line in output.read_text(errors='replace').splitlines():
                            fields=line.split('*')
                            if len(fields)>=6 and fields[0]=='WPA' and fields[1] in ('01','02') and fields[3].lower()==wanted:usable=True;break
                    self.events.put(('probe',prefix,target,usable))
            except Exception:self.events.put(('probe',prefix,target,False))
        threading.Thread(target=worker,daemon=True).start()

    def refresh(self):
        app=self.app;r=self.recovery;c=app.coach_panel
        if app.closing:return
        try:
            for _ in range(10):
                kind,prefix,target_bssid,usable=self.events.get_nowait();self.probing=False
                if usable and prefix==app.capture_prefix and target_bssid==(app.selected_target or {}).get('bssid',''):
                    self.ready_prefix=prefix
                    if app.proc and not app.stopping and self.auto_stop_requested_for!=prefix:
                        self.auto_stop_requested_for=prefix
                        if not app.capture_focused:app.pending_scan_recovery=True
                        app._log('Usable WPA2 record found. Stopping capture automatically.')
                        self.after_idle(app.stop_capture)
        except queue.Empty:pass
        if app.proc and app.selected_target:
            self.probe()
        app.capture_feedback.update(self.ready_prefix)
        app.client_suitability.refresh()
        app.reconnect_panel.refresh()
        self.reconnect_panel.refresh()
        target=app.selected_target
        names=[d.name for d in r.devices]
        self.gpu.configure(values=names)
        chosen=next((d for d in r.devices if d.label==r.device_var.get()),None)
        self.gpu_var.set(chosen.name if chosen else 'Detecting GPUs…' if not names else 'Choose a GPU')
        locked=app.admin_busy or app.stopping or app.pending_focused
        section='network';stage=0;enabled=True
        title='Pick your Wi-Fi network'
        detail='Tap Find networks to start.'
        action='⌕ Find networks'
        context='LET’S BEGIN'
        if r.job_running or r.ready_hash or r.saved_session:
            section='recovery';stage=2;context=target['essid'] if target else 'SAVED CAPTURE'
            if r.job_running:
                title='Trying passwords…';detail='Pause & save lets you close AirWatch and resume later.';action='Ⅱ Pause & save'
            elif r.saved_session:
                title='Your search is saved';detail='Pick up from the saved checkpoint.';action='▶ Resume saved'
            elif r.recovered_plain:
                title='Password found!';detail='Tap Reveal password below.';action='Try another search'
            else:
                title='Ready to try passwords';detail='Choose a pattern or wordlist.';action='▶ Start search'
                enabled=chosen is not None
        elif app.proc and app.capture_focused:
            section='capture';stage=1;context=(f"{target['essid']} · {channel_band(target.get('channel'))} · channel {target.get('channel')}" if target else 'CAPTURING')
            title='Listening for a handshake…';detail='Connect one of your devices. Capture stops when a usable record appears.';action='■ Stop & check'
        elif target:
            stage=1;context=f"{target['essid']} · {channel_band(target.get('channel'))} · channel {target.get('channel')}";action='◉ Capture handshake'
            if app.capture_focused and app.capture_prefix:
                section='capture';title='No usable handshake yet';detail='Connect a device and try again.';action='◉ Capture again'
                if str(r.analyze_btn.cget('state'))=='disabled':title='Checking your capture…';detail='Looking for a usable handshake from the selected network.';enabled=False
            else:
                title='Ready to capture this network';detail='AirWatch will stay on its channel and look for a handshake.'
            if app.proc and not app.capture_focused and app.client_suitability.complete_record_observed():
                title='WPA2 handshake traffic found in the scan'
                detail='Stop and check these captured packets for a usable recovery record.'
                action='Stop & check WPA2 capture'
            suitability, reason=app.client_suitability.state()
            if suitability=='unsupported':
                title='WPA2-Personal is unavailable here'
                detail=reason
                action='Choose a WPA2 network'
                enabled=False
            elif suitability=='needs_client' and not (app.proc and not app.capture_focused and app.client_suitability.complete_record_observed()):
                title='Ready to capture this WPA2 network'
                detail=reason
        elif app.proc:
            title='Select your network below';detail='Scanning nearby networks. Select the one you own or are authorized to test.';action='Select a network';enabled=False
        if self.visible_section is None:self.set_section(section)
        if section=='recovery' and self.visible_section!='recovery':action='◇ Open Recovery'
        elif self.visible_section!='network' and not target:
            action='⌁ Open Networks';enabled=True
        elif self.visible_section=='recovery' and section!='recovery':
            action='◉ Open Capture'
        if locked:
            detail='Sending a short reconnect burst. Capture is still running; controls return when it finishes.' if app.deauth_inflight else 'Finishing the current operation…'
            enabled=False
        self.context_var.set(context);self.title_var.set(title);self.detail_var.set(self.notice or detail);self.action_var.set(action)
        self.primary.state(['!disabled'] if enabled and not locked else ['disabled'])
        if target:
            if not self.back_btn.winfo_manager():self.back_btn.pack(side='right',padx=(0,8),before=self.advanced_btn)
            self.back_btn.configure(text='Stop & choose network…' if app.proc else '← Choose another network')
            self.back_btn.state(['disabled'] if r.job_running or locked or app.pending_network_return else ['!disabled'])
        else:self.back_btn.pack_forget()
        self.reconnect_toggle.state(['disabled'] if r.job_running or not app.client_suitability.can_capture() else ['!disabled'])
        self.scan_stop.state(['!disabled'] if app.proc and not app.capture_focused and not locked else ['disabled'])
        raw_rows=tuple((iid,tuple(app.table.item(iid,'values'))) for iid in app.table.get_children())
        wpa2_rows=tuple((iid,v) for iid,v in raw_rows if len(v)>=5 and 'WPA2' in str(v[2]).upper())
        connected={v.get('ssid') for v in app.interfaces.values() if v.get('ssid')}
        needle=self.network_filter.get().strip().casefold()
        rows=tuple(sorted(((iid,v) for iid,v in wpa2_rows if not needle or needle in v[4].casefold()),
                          key=lambda row:(row[1][4] not in connected,row[1][4].startswith('<'),row[1][4].casefold(),row[0])))
        if rows!=self.rows:
            self.rows=rows;self.picking=True
            position=self.networks.yview()[0]
            existing=set(self.networks.get_children());wanted_ids={iid for iid,_ in rows}
            for iid in existing-wanted_ids:self.networks.delete(iid)
            for index,(iid,values) in enumerate(rows):
                bssid,ch,security,power,name=values[:5]
                try:
                    dbm=int(power);signal='Strong' if dbm>=-55 else 'Good' if dbm>=-67 else 'Fair' if dbm>=-75 else 'Weak'
                except ValueError:signal=power
                shown=name+'  · connected' if name in connected else name
                display=(shown,'WPA2-Personal',channel_band(ch),signal,ch)
                if iid in existing:self.networks.item(iid,values=display)
                else:self.networks.insert('','end',iid=iid,values=display)
                self.networks.move(iid,'',index)
            self.networks.yview_moveto(position)
            if target and target['bssid'] in wanted_ids and self.networks.selection()!=(target['bssid'],):
                self.networks.selection_set(target['bssid'])
            self.picking=False
        if needle and not rows:empty_text=f'No WPA2 network matches “{self.network_filter.get()}”. Clear the search to see all {len(wpa2_rows)} WPA2 networks.'
        elif rows:empty_text=f'{len(rows)} WPA2 networks shown. Your connected network appears first.'
        elif app.proc:empty_text='Scanning for access points that advertise WPA2-Personal…'
        elif raw_rows:empty_text='Nearby access points were found, but none advertise WPA2-Personal. Choose a WPA2-capable network for this workflow.'
        else:empty_text='Choose Find networks to look for WPA2-Personal access points.'
        self.empty.configure(text=empty_text)
        snapshot=c.current_snapshot()
        current_source=app.capture_prefix+'-01.cap' if app.capture_prefix else ''
        if snapshot:
            packets=snapshot['frames_observed'];eapol=snapshot['eapol_frames'];consistent=snapshot['consistent_exchanges']
            self.capture_metrics.configure(text=f'{packets:,} packets received    ·    {eapol:,} handshake frames    ·    {consistent} complete exchange(s)')
            if section=='capture' and app.proc and consistent:
                self.title_var.set('Handshake messages received');self.detail_var.set('Stop and check the capture to confirm it contains a usable recovery record.')
        else:self.capture_metrics.configure(text='Reading packet evidence…' if app.proc else 'No usable recovery record found.')
        if section=='capture' and app.proc and current_source:
            try:
                if Path(current_source).stat().st_size>=16*1024*1024:
                    self.title_var.set('Large capture — stop and check it')
                    self.detail_var.set('Live previews have paused to keep the app responsive. Stop and check the full capture for a usable handshake.')
            except OSError:pass
        if section=='capture' and snapshot:
            if snapshot.get('sae_exchanges'):
                self.title_var.set('Exchange received — not usable for WPA2 recovery')
                self.detail_var.set('This exchange cannot produce the WPA2 recovery record. Use a device confirmed to connect with WPA2-Personal, then capture its reconnection.')
            elif snapshot.get('unsupported_akm_exchanges'):
                self.title_var.set('Exchange received — recovery unsupported')
                self.detail_var.set('This exchange uses an unsupported key descriptor. A WPA2-PSK client connection is needed for this test.')
        elif section=='capture' and r.analysis_var.get().startswith('Captured an unsupported'):
            self.title_var.set('Exchange received — recovery unsupported')
            self.detail_var.set(r.analysis_var.get())
        if section=='capture' and app.proc and app.capture_feedback.level==4:
            self.title_var.set('Handshake captured — ready for recovery')
            self.detail_var.set('Stopping capture and checking the handshake…')
        self.progress.configure(value=r.progress.cget('value'))
        self.reveal.configure(text='Hide password' if r.reveal_btn.cget('text')=='Hide' else 'Reveal password')
        self.reveal.state(['!disabled'] if r.recovered_plain else ['disabled'])
        for widget in (self.pattern_box,self.gpu):widget.configure(state='disabled' if r.job_running else 'readonly')
        self.estimate_btn.state(['disabled'] if r.job_running or r.estimate_proc is not None or not r.ready_hash else ['!disabled'])
        self.after(250,self.refresh)


def app_stop(app):
    return app.stop_capture
