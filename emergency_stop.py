"""Independent stop launcher: works without the AirWatch Tk event loop."""
import json
import os
import signal
import socket
import sys
import tempfile
import time
from pathlib import Path

WORKER_NAMES = {'hashcat', 'tshark', 'dumpcap', 'hcxpcapngtool', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'iw', 'pkexec'}


def is_worker(item):
    if item['name'] in WORKER_NAMES:return True
    if item['name'].startswith('python'):
        try:
            args=Path(f"/proc/{item['pid']}/cmdline").read_bytes().split(b'\0')
            return str(Path(__file__).with_name('next_step_worker.py')).encode() in args
        except OSError:pass
    return False


def process_info(pid):
    try:
        text = Path(f'/proc/{pid}/stat').read_text()
        end = text.rfind(')')
        fields = text[end+2:].split()
        return {'pid': int(pid), 'parent': int(fields[1]), 'start': fields[19],
                'name': text[text.find('(')+1:end]}
    except (OSError, ValueError, IndexError):
        return None


def create_session_directory():
    runtime = Path(f'/run/user/{os.getuid()}')
    if not runtime.is_dir() or runtime.stat().st_uid != os.getuid():
        raise RuntimeError('The private desktop runtime directory is unavailable.')
    directory = Path(tempfile.mkdtemp(prefix='airwatch-stop-', dir=runtime))
    info = process_info(os.getpid())
    path = directory/'session.json'
    path.write_text(json.dumps({'pid': os.getpid(), 'start': info['start']}))
    path.chmod(0o600)
    return directory


def stop_session(directory):
    directory = Path(directory)
    if directory.is_symlink() or directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        raise RuntimeError('Emergency session directory is not private.')
    stopped_at = time.time_ns()
    marker = directory/'stop'
    # The marker also cancels commands still waiting at the system authorization prompt.
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(str(stopped_at))
    result = {'requested_at': stopped_at, 'helper_reached': False, 'workers_stopped': [], 'errors': []}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(1)
            channel.connect(str(directory/'control.sock'))
            channel.sendall(b'STOP\n')
            reply = json.loads(channel.recv(4096))
            result['helper_reached'] = bool(reply.get('accepted'))
            result['workers_stopped'].extend(reply.get('pids', []))
    except FileNotFoundError:
        pass  # No privileged session yet, or authorization is still pending.
    except (OSError, ValueError) as exc:
        result['errors'].append(str(exc))
    try:
        session = json.loads((directory/'session.json').read_text())
        root = process_info(session['pid'])
        if not root or root['start'] != session['start']:
            return result
        for _ in range(3):
            infos = [item for entry in Path('/proc').iterdir() if entry.name.isdigit()
                     if (item := process_info(entry.name))]
            descendants = {root['pid']}
            changed = True
            while changed:
                before = len(descendants)
                descendants.update(i['pid'] for i in infos if i['parent'] in descendants)
                changed = len(descendants) != before
            for item in infos:
                if item['pid'] != root['pid'] and item['pid'] in descendants and is_worker(item):
                    current = process_info(item['pid'])
                    if not current or current['start'] != item['start']:
                        continue
                    try:
                        os.kill(item['pid'], signal.SIGKILL)
                        result['workers_stopped'].append(item['pid'])
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        if not result['helper_reached']:
                            result['errors'].append('A privileged worker could not be reached through its helper.')
            time.sleep(.1)
    except (OSError, ValueError, KeyError) as exc:
        result['errors'].append(str(exc))
    result['workers_stopped'] = sorted(set(result['workers_stopped']))
    return result


def stop_all_sessions():
    results = []
    for directory in Path(f'/run/user/{os.getuid()}').glob('airwatch-stop-*'):
        try:
            session=json.loads((directory/'session.json').read_text())
            info=process_info(session['pid'])
            if not (info and info['start']==session['start']) and not (directory/'control.sock').exists():continue
            results.append(stop_session(directory))
        except (OSError,ValueError,KeyError):
            continue
    return results


if __name__ == '__main__':
    results = stop_all_sessions()
    errors = [e for result in results for e in result['errors']]
    message = ('Emergency stop sent to AirWatch sessions. Capture, reconnect, analysis and recovery workers were interrupted. '
               'The last packet may be incomplete. Adapter restoration is attempted separately.' if results else 'No AirWatch sessions were found.')
    if errors:
        message += '\n\nSome processes could not be confirmed stopped:\n' + '\n'.join(errors)
    print(message)
    if '--no-dialog' not in sys.argv:
        import tkinter as tk
        from tkinter import messagebox
        window = tk.Tk(); window.withdraw()
        (messagebox.showwarning if errors else messagebox.showinfo)('AirWatch emergency stop', message)
        window.destroy()
