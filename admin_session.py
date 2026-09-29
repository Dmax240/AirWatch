"""One PolicyKit authorization per app session; passwords never enter the app."""
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from emergency_stop import create_session_directory, stop_session


class AdminSession:
    def __init__(self):
        self.process = None
        self.lock = threading.Lock()
        self.control_dir = create_session_directory()
        self.stopped_at = 0

    def emergency_stop(self):
        # Deliberately does not acquire the normal request lock.
        self.stopped_at = time.time_ns()
        return stop_session(self.control_dir)

    def request(self, operation, **parameters):
        issued_at = time.time_ns()
        with self.lock:
            if operation in ('run','capture','deauth') and issued_at <= self.stopped_at:
                raise RuntimeError('Operation cancelled by emergency stop.')
            if self.process is None or self.process.poll() is not None:
                helper = str(Path(__file__).with_name('privileged_helper.py'))
                command = ['/usr/bin/python3', '-I', helper, '--control', str(self.control_dir/'control.sock')]
                if os.geteuid() != 0:
                    pkexec = shutil.which('pkexec')
                    if not pkexec:
                        raise RuntimeError('PolicyKit is missing; cannot authorize the session.')
                    command.insert(0, pkexec)
                self.process = subprocess.Popen(command, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                    bufsize=1, start_new_session=True)
            process = self.process
            process.stdin.write(json.dumps({'op': operation, 'issued_at':issued_at, **parameters}) + '\n')
            process.stdin.flush()
            if not select.select([process.stdout], [], [], 150)[0]:
                process.stdin.close()  # EOF makes the helper clean up.
                raise RuntimeError('Authorization or administrative operation timed out.')
            response = process.stdout.readline()
            if not response:
                raise RuntimeError('Administrator session ended or authorization was cancelled.')
            data = json.loads(response)
            if 'error' in data:
                raise RuntimeError(data['error'])
            return data

    def run(self, args):
        result = self.request('run', args=args)
        return subprocess.CompletedProcess(args, result['returncode'], result['stdout'], result['stderr'])

    def close(self):
        if self.process and self.process.poll() is None:
            try:
                self.request('cleanup')
            finally:
                self.process.stdin.close()
        shutil.rmtree(self.control_dir, ignore_errors=True)


class CaptureProcess:
    """Small process-like adapter; only the privileged owner signals capture."""
    def __init__(self, session, args):
        self.session = session
        result = session.request('capture', args=args)
        self.pid = result['pid']
        self.command = list(args)
        self.output = ''
        self.returncode = None
        self.reason = ''

    def poll(self):
        status = self.session.request('status')
        self.returncode = status['returncode']
        self.reason = status.get('reason', '')
        self.output = status.get('output', '')
        return self.returncode

    def stop(self):
        status = self.session.request('stop')
        self.returncode = status['returncode']
        self.reason = status.get('reason', '')
        self.output = status.get('output', '')
