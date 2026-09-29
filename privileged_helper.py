#!/usr/bin/python3
"""Private stdio helper. Fixed administrative operations, no shell commands.

Owns capture signals and cleanup; EOF from the GUI triggers restoration.
"""
import json
import csv
import os
import re
import resource
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

TOOLS = {name: shutil.which(name) for name in ('airmon-ng','airodump-ng','aireplay-ng','iw','ip','systemctl','nmcli','apt-get')}
SERVICES = ('NetworkManager.service','wpa_supplicant.service')


ACTIVE_RUNS = set()
RUN_LOCK = threading.Lock()
STOP_EVENT = threading.Event()
RUN_CONTEXT = threading.local()


def run(args, timeout=35):
    with RUN_LOCK:
        if STOP_EVENT.is_set() and not getattr(RUN_CONTEXT,'cleanup',False):
            raise RuntimeError('Emergency stop requested.')
        p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
        ACTIVE_RUNS.add(p)
    try:
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:pass
            out, err = p.communicate()
            return {'returncode':124,'stdout':out[-65536:], 'stderr':err[-65536:]+'\nOperation timed out.'}
        return {'returncode':p.returncode, 'stdout':out[-65536:], 'stderr':err[-65536:]}
    finally:
        with RUN_LOCK:ACTIVE_RUNS.discard(p)


def interfaces():
    result = run([TOOLS['iw'],'dev'],10)
    if result['returncode']:raise RuntimeError(result['stderr'] or 'Cannot read adapters')
    found={};phy=None;name=None
    for line in result['stdout'].splitlines():
        line=line.strip()
        if line.startswith('phy#'):phy=line;name=None
        elif line.startswith('Unnamed/'):name=None
        elif line.startswith('Interface '):
            name=line.split()[1];found[name]={'phy':phy}
        elif name and line.startswith('type '):found[name]['mode']=line.split()[1]
    return found


class Helper:
    def __init__(self):
        self.capture=None
        self.phys=set()
        self.services=set()
        self.reason=''
        self.tail=bytearray()
        self.output_bytes=0
        self.capture_prefix=None
        self.capture_config={}
        self.capture_iface=None
        self.last_deauth=0
        self.reader=None
        self.started=0
        self.last_cpu=None
        self.finished_cleanup=False
        self.high_cpu=0
        self.uid=int(os.environ.get('PKEXEC_UID',os.getuid()))
        self.stop_at=0
        self.emergency_cleanup_pending=False
        self.control=None

    def start_control(self,path):
        path=Path(path);parent=path.parent
        if path.name!='control.sock' or parent.parent!=Path(f'/run/user/{self.uid}') or not parent.name.startswith('airwatch-stop-'):
            raise ValueError('Invalid emergency control location.')
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=self.uid or info.st_mode&0o077:
            raise ValueError('Emergency control directory must be private and owned by the app user.')
        marker=parent/'stop'
        if marker.exists():
            self.stop_at=int(marker.read_text())
            STOP_EVENT.set()
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        server.bind(str(path));os.chown(path,self.uid,-1);os.chmod(path,0o600)
        server.listen(2);server.settimeout(1);self.control=server
        def listen():
            while self.control is server:
                try:
                    connection,_=server.accept()
                except socket.timeout:continue
                except OSError:return
                with connection:
                    connection.settimeout(1)
                    try:
                        _,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                        if uid!=self.uid or connection.recv(16)!=b'STOP\n':continue
                        pids=self.emergency_stop()
                        connection.sendall(json.dumps({'accepted':True,'pids':pids}).encode())
                    except (OSError,ValueError):continue
        threading.Thread(target=listen,daemon=True).start()

    def emergency_stop(self):
        self.stop_at=time.time_ns();STOP_EVENT.set()
        self.reason='Emergency stop requested. Work was interrupted; adapter restoration follows.'
        pids=[]
        with RUN_LOCK:
            processes=set(ACTIVE_RUNS)
            if self.capture:processes.add(self.capture)
            for process in processes:
                if process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGKILL);pids.append(process.pid)
                    except ProcessLookupError:pass
        self.emergency_cleanup_pending=True
        return pids


    def stop(self):
        self.finished_cleanup=True
        if self.capture and self.capture.poll() is None:
            for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGKILL):
                try:os.killpg(self.capture.pid,sig)
                except ProcessLookupError:break
                try:self.capture.wait(timeout=2);break
                except subprocess.TimeoutExpired:continue
        if self.reader:self.reader.join(timeout=2)
        self.save_output()
        return self.status()

    def save_output(self):
        if not self.capture_prefix:return
        # Refuse symlinks for the diagnostic file. Keep only the last 64 KiB.
        try:
            fd=os.open(self.capture_prefix+'.log',os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as f:
                f.write(bytes(self.tail));f.write(('\n'+self.reason+'\n').encode())
                os.fchown(f.fileno(),self.uid,-1)
            if self.capture and self.capture.poll() is not None:
                prefix=Path(self.capture_prefix)
                for p in prefix.parent.glob(prefix.name+'-*'):
                    if p.is_file() and not p.is_symlink():os.chown(p,self.uid,-1)
        except OSError:pass

    def status(self):
        return {'returncode': self.capture.poll() if self.capture else 0,'reason':self.reason,
                'output':bytes(self.tail[-16384:]).decode(errors='replace'),'emergency_stopped_at':self.stop_at}

    def restore(self):
        previous=getattr(RUN_CONTEXT,'cleanup',False)
        RUN_CONTEXT.cleanup=True
        try:return self._restore()
        finally:RUN_CONTEXT.cleanup=previous

    def _restore(self):
        self.stop()
        errors=[]
        try:
            for name,item in interfaces().items():
                if item['phy'] in self.phys and item.get('mode')=='monitor':
                    result=run([TOOLS['airmon-ng'],'stop',name])
                    if result['returncode']:errors.append(result['stderr'] or result['stdout'])
            # Some mac80211 USB drivers keep the same interface name and airmon
            # reports success without changing its type. Verify and restore it.
            for name,item in interfaces().items():
                if item['phy'] in self.phys and item.get('mode')=='monitor':
                    for command in ([TOOLS['ip'],'link','set','dev',name,'down'],
                                    [TOOLS['iw'],'dev',name,'set','type','managed'],
                                    [TOOLS['ip'],'link','set','dev',name,'up']):
                        result=run(command)
                        if result['returncode']:
                            errors.append(result['stderr'] or result['stdout']);break
            remaining={v['phy'] for v in interfaces().values() if v.get('mode')=='monitor'}
            self.phys.intersection_update(remaining)
            if self.phys:errors.append('An adapter is still in monitor mode after restoration.')
        except Exception as e:errors.append(str(e))
        if self.services:
            result=run([TOOLS['systemctl'],'start',*sorted(self.services)])
            if result['returncode']:errors.append(result['stderr'] or result['stdout'])
            else:self.services.clear()
        if errors:raise RuntimeError('Cleanup incomplete: '+'\n'.join(errors))
        return {'ok':True}

    def restore_wifi(self, selected_interface=None):
        """Stop our capture, restore its radio, and re-enable normal Wi-Fi."""
        previous=getattr(RUN_CONTEXT,'cleanup',False)
        RUN_CONTEXT.cleanup=True
        try:return self._restore_wifi(selected_interface)
        finally:RUN_CONTEXT.cleanup=previous

    def _restore_wifi(self, selected_interface=None):
        errors=[]
        try:before=interfaces()
        except Exception as exc:
            before={}
            errors.append('Could not inspect adapters: '+str(exc))
        if selected_interface in before:
            if before[selected_interface].get('mode')=='monitor':
                self.phys.add(before[selected_interface]['phy'])
        affected=set(self.phys)
        try:self.restore()
        except Exception as exc:errors.append(str(exc))
        manager=run([TOOLS['systemctl'],'restart','NetworkManager.service'],timeout=45)
        if manager['returncode']:
            errors.append('NetworkManager restart: '+(manager['stderr'] or manager['stdout']).strip())
        # Some systems run wpa_supplicant under NetworkManager rather than a
        # standalone unit. Restart the unit only when it is already active.
        if run([TOOLS['systemctl'],'is-active','--quiet','wpa_supplicant.service'])['returncode']==0:
            supplicant=run([TOOLS['systemctl'],'restart','wpa_supplicant.service'],timeout=45)
            if supplicant['returncode']:
                errors.append('wpa_supplicant restart: '+(supplicant['stderr'] or supplicant['stdout']).strip())
        nmcli=TOOLS['nmcli']
        if nmcli:
            for command in ([nmcli,'networking','on'],[nmcli,'radio','wifi','on']):
                result=run(command,timeout=20)
                if result['returncode']:
                    errors.append(' '.join(command[1:])+': '+(result['stderr'] or result['stdout']).strip())
            managed=[]
            try:after=interfaces()
            except Exception as exc:
                after={}
                errors.append('Could not verify adapters: '+str(exc))
            for name,item in after.items():
                if item['phy'] in affected and item.get('mode')=='managed':
                    managed.append(name)
                    result=run([nmcli,'device','set',name,'managed','yes'],timeout=20)
                    if result['returncode']:
                        errors.append(name+': '+(result['stderr'] or result['stdout']).strip())
            connected=False
            for _ in range(10):
                status=run([nmcli,'-t','-f','DEVICE,TYPE,STATE','device','status'],timeout=20)
                connected=any(':wifi:connected' in line for line in status['stdout'].splitlines())
                if connected:break
                time.sleep(1)
            if not connected:
                for name in managed:
                    # This asks NetworkManager to use an existing saved profile.
                    # A missing profile remains a user choice in the Wi-Fi menu.
                    run([nmcli,'--wait','15','device','connect',name],timeout=20)
                status=run([nmcli,'-t','-f','DEVICE,TYPE,STATE','device','status'],timeout=20)
                connected=any(':wifi:connected' in line for line in status['stdout'].splitlines())
        else:
            connected=False
            errors.append('nmcli is unavailable, so Wi-Fi radio and connection state could not be verified.')
        if errors:raise RuntimeError('Wi-Fi restoration incomplete: '+'; '.join(errors))
        return {'ok':True,'connected':connected,'interfaces':after}

    def administrative(self,args):
        if self.capture and self.capture.poll() is None:raise RuntimeError("Stop capture before changing administrative settings.")
        if not isinstance(args,list) or not all(isinstance(x,str) for x in args):raise ValueError('Invalid command')
        command=args[0];rest=args[1:]
        if command==TOOLS['airmon-ng']:
            if rest not in (['check'],['check','kill']):
                if len(rest)!=2 or rest[0] not in ('start','stop') or rest[1] not in interfaces():raise ValueError('Unsupported adapter operation')
                # Track before running so partial mode-change failures can be restored.
                if rest[0]=='start':self.phys.add(interfaces()[rest[1]]['phy'])
            if rest==['check','kill']:
                for service in SERVICES:
                    if run([TOOLS['systemctl'],'is-active','--quiet',service])['returncode']==0:self.services.add(service)
            result=run(args)
        elif command==TOOLS['systemctl'] and rest==['restart',*SERVICES]:
            result=run(args)
            if result['returncode']==0:self.services.clear()
        elif command==TOOLS['apt-get'] and rest==['install','-y','hcxtools']:
            result=run(args,120)
        else:raise ValueError('Administrative command is not allowed')
        return result

    def start(self,args):
        if self.capture and self.capture.poll() is None:raise RuntimeError('Capture is already running')
        if not isinstance(args,list) or args[0]!=TOOLS['airodump-ng']:raise ValueError('Invalid capture tool')
        options={'--write','--output-format','--background','--update','--write-interval','--band','--channel','--bssid'}
        opts={}
        i=1
        while i<len(args)-1:
            if args[i] not in options or i+1>=len(args)-1:raise ValueError('Unsupported capture option')
            opts[args[i]]=args[i+1];i+=2
        iface=args[-1]
        info=interfaces().get(iface)
        if not info or info.get('mode')!='monitor':raise ValueError('Selected adapter is no longer in monitor mode')
        if opts.get('--background')!='1':raise ValueError('Headless capture is required')
        prefix=Path(opts['--write'])
        if not prefix.is_absolute() or not re.fullmatch(r'capture_[\w-]+',prefix.name):raise ValueError('Invalid capture path')
        if not prefix.parent.is_dir() or prefix.parent.stat().st_uid!=self.uid:raise ValueError('Choose an output folder owned by your user')
        if any(prefix.parent.glob(prefix.name+'*')):raise ValueError('Capture path already exists')
        self.phys.add(info['phy'])
        self.capture_config=dict(opts);self.capture_iface=iface
        self.capture_prefix=str(prefix);self.tail=bytearray();self.reason='';self.output_bytes=0
        nice=shutil.which('nice');prlimit=shutil.which('prlimit')
        if not nice or not prlimit:raise RuntimeError('nice and prlimit are required for bounded capture.')
        # Avoid Python preexec_fn in a helper with a control thread: fork callbacks
        # can deadlock before exec. The wrappers apply the same limits then exec.
        bounded=[nice,'-n','10',prlimit,'--fsize=536870912:536870912','--',*args]
        with RUN_LOCK:
            if STOP_EVENT.is_set():raise RuntimeError('Emergency stop requested.')
            self.capture=subprocess.Popen(bounded,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                          start_new_session=True)
        capture=self.capture
        def drain():
            while True:
                data=capture.stdout.read1(8192)
                if not data:break
                self.output_bytes+=len(data)
                self.tail.extend(data)
                del self.tail[:-65536]
        self.reader=threading.Thread(target=drain,daemon=True);self.reader.start()
        self.started=time.monotonic();self.last_cpu=None;self.high_cpu=0;self.finished_cleanup=False
        return {'pid':capture.pid}

    def deauth(self,request):
        if not self.capture or self.capture.poll() is not None:raise RuntimeError('Start a focused capture first.')
        ap=self.capture_config.get('--bssid','').lower()
        if not ap or '--channel' not in self.capture_config:raise ValueError('A focused, fixed-channel capture is required.')
        if str(request.get('bssid','')).lower()!=ap or request.get('capture_prefix')!=self.capture_prefix:
            raise ValueError('The confirmed capture or access point changed. Confirm the current selection again.')
        scope=request.get('scope')
        if scope not in ('client','network'):raise ValueError('Choose one device or the whole selected network explicitly.')
        client=str(request.get('client','')).lower()
        if scope=='client' and (not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',client) or int(client[:2],16)&1 or client==ap):
            raise ValueError('Choose a valid individual client MAC address.')
        if scope=='network' and client:raise ValueError('Whole-network scope cannot include an individual client.')
        count=request.get('count');reason=request.get('reason')
        if type(count) is not int or not 1<=count<=5 or reason not in (1,3,7):raise ValueError('Invalid burst count or reason code.')
        if time.monotonic()-self.last_deauth<15:raise RuntimeError('Wait 15 seconds between reconnect tests.')
        if scope=='client':
            path=Path(self.capture_prefix+'-01.csv')
            if not path.is_file() or path.stat().st_size>8*1024*1024:raise RuntimeError('Current capture client list is unavailable.')
            observed=False;stations=False
            with path.open(errors='replace') as f:
                for row in csv.reader(f):
                    if row and row[0].strip()=='Station MAC':stations=True;continue
                    if stations and len(row)>=6 and row[0].strip().lower()==client and row[5].strip().lower()==ap:
                        observed=True;break
            if not observed:raise ValueError('This client was not observed associated with the selected AP in this capture.')
        info=interfaces().get(self.capture_iface)
        if not info or info.get('mode')!='monitor':raise RuntimeError('Capture adapter is no longer in monitor mode.')
        if not TOOLS['aireplay-ng']:raise RuntimeError('aireplay-ng is unavailable.')
        self.last_deauth=time.monotonic()
        args=[TOOLS['aireplay-ng'],'--deauth',str(count),'--deauth-rc',str(reason),'-a',ap]
        if scope=='client':args.extend(['-c',client])
        return run([*args,self.capture_iface],timeout=12)

    def watchdog(self):
        if self.emergency_cleanup_pending:
            self.emergency_cleanup_pending=False
            self.restore()
            return
        if not self.capture:return
        if self.capture.poll() is not None:
            if not self.finished_cleanup:
                self.finished_cleanup=True
                if not self.reason:self.reason=f"Capture exited with code {self.capture.returncode}."
                self.restore()
            return
        elapsed=time.monotonic()-self.started
        reason=''
        if shutil.disk_usage(Path(self.capture_prefix).parent).free<1024**3:
            reason='Capture stopped: less than 1 GiB of disk space remains.'
        if self.output_bytes>2*1024*1024:reason='Capture stopped: excessive diagnostic output.'
        if elapsed>1800:reason='Capture stopped at the 30-minute safety limit.'
        csv_path=Path(self.capture_prefix+'-01.csv')
        cap_path=Path(self.capture_prefix+'-01.cap')
        if elapsed>30 and (not csv_path.exists() or csv_path.stat().st_size==0):reason='Capture stopped: no CSV output after 30 seconds.'
        if elapsed>60 and (not cap_path.exists() or cap_path.stat().st_size<=24):reason='Capture stopped: no packets received in 60 seconds. Check adapter firmware, band and driver.'
        try:
            fields=Path(f'/proc/{self.capture.pid}/stat').read_text().split()
            ticks=int(fields[13])+int(fields[14]);now=time.monotonic()
            if self.last_cpu:
                old_time,old_ticks=self.last_cpu
                usage=(ticks-old_ticks)/os.sysconf('SC_CLK_TCK')/max(.01,now-old_time)
                self.high_cpu=self.high_cpu+(now-old_time) if usage>.8 else 0
                if self.high_cpu>8:reason='Capture stopped: sustained excessive CPU usage.'
            self.last_cpu=(now,ticks)
        except (OSError,ValueError):pass
        if reason:
            self.reason=reason;self.restore()

    def handle(self,request):
        op=request['op']
        if op in ('run','capture','deauth') and self.stop_at:
            if request.get('issued_at',0)<=self.stop_at:raise RuntimeError('Operation cancelled by emergency stop.')
            STOP_EVENT.clear()
        if op=='run':return self.administrative(request['args'])
        if op=='capture':return self.start(request['args'])
        if op=='deauth':return self.deauth(request)
        if op=='status':return self.status()
        if op=='stop':return self.stop()
        if op=='cleanup':return self.restore()
        if op=='restore_wifi':return self.restore_wifi(request.get('interface'))
        raise ValueError('Unknown operation')


def main():
    if os.geteuid()!=0:raise SystemExit('Administrator authorization is required')
    os.umask(0o022)
    helper=Helper()
    if len(sys.argv)==3 and sys.argv[1]=='--control':helper.start_control(sys.argv[2])
    # Unbuffered fd reads avoid read-ahead surprises with select().
    pending=b''
    try:
        while True:
            if select.select([sys.stdin],[],[],1)[0]:
                data=os.read(sys.stdin.fileno(),65536)
                if not data:break
                pending+=data
                if len(pending)>262144:raise ValueError('Request exceeds size limit')
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1)
                    try:response=helper.handle(json.loads(line))
                    except Exception as e:response={'error':str(e)}
                    print(json.dumps(response),flush=True)
            try:helper.watchdog()
            except Exception as e:helper.reason=str(e)
    finally:
        if helper.control:
            control_path=helper.control.getsockname()
            helper.control.close();helper.control=None
            try:Path(control_path).unlink(missing_ok=True)
            except OSError:pass
        try:helper.restore()
        except Exception:pass

if __name__=='__main__':main()
