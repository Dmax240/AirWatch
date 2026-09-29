"""Private metadata for one resumable Hashcat search."""
import json
import os
import tempfile
from pathlib import Path

from preferences import settings_path


def pointer_path():
    return settings_path().with_name('saved-search.json')


def _atomic_json(path, data):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,prefix='.airwatch-',delete=False) as stream:
            temporary=Path(stream.name)
            os.chmod(temporary,0o600)
            json.dump(data,stream)
            stream.write('\n')
        os.replace(temporary,path)
    finally:
        if temporary:temporary.unlink(missing_ok=True)


def write_manifest(path, data):
    _atomic_json(path,data)


def remember(path):
    _atomic_json(pointer_path(),{'version':1,'manifest':str(Path(path).resolve())})


def load_saved():
    try:
        pointer=json.loads(pointer_path().read_text())
        if pointer.get('version')!=1:return None
        path=Path(pointer['manifest']).expanduser()
        data=json.loads(path.read_text())
        required=('session','restore_file','hashfile','result_path','run_dir')
        if data.get('version')!=1 or not all(isinstance(data.get(key),str) and data[key] for key in required):
            return None
        data['manifest_path']=str(path)
        return data
    except (OSError,ValueError,KeyError,TypeError):
        return None


def clear_if_current(path):
    saved=load_saved()
    if saved and saved['manifest_path']==str(Path(path).resolve()):
        try:pointer_path().unlink(missing_ok=True)
        except OSError:pass


def process_active(data):
    """Avoid launching the same saved search in a second AirWatch window."""
    try:
        pid=int(data.get('pid',0))
        if pid<2:return False
        command=Path(f'/proc/{pid}/cmdline').read_bytes()
        return b'hashcat' in command and str(data['session']).encode() in command
    except (OSError,ValueError,KeyError):
        return False
