"""Small local preferences file; excludes credentials, results and device IDs."""
import json
import os
from pathlib import Path
import tempfile
from phone_area_codes import STATE_AREA_CODES

PHONE_FORMATS=('Both styles','Digits only','With dashes')


def settings_path():
    override=os.environ.get('AIRWATCH_PREFERENCES_FILE')
    return Path(override).expanduser() if override else Path.home()/'.config/airwatch/preferences.json'


def clean(data):
    if not isinstance(data,dict):return {}
    result={}
    if data.get('method') in ('wordlist','mask','phone','state_phone'):
        result['method']=data['method']
    if data.get('phone_state') in STATE_AREA_CODES:
        result['phone_state']=data['phone_state']
    if data.get('phone_format') in PHONE_FORMATS:
        result['phone_format']=data['phone_format']
    for key in ('lower','upper','digits','symbols','fast_workload','optimized','auto_ai'):
        if isinstance(data.get(key),bool):result[key]=data[key]
    for key,low,high in (('min_len',8,63),('max_len',8,63),('temperature',60,90),('runtime',0,86400)):
        value=data.get(key)
        if type(value) is int and low<=value<=high:result[key]=value
    if result.get('min_len',8)>result.get('max_len',63):
        result.pop('min_len',None);result.pop('max_len',None)
    if isinstance(data.get('wordlist_path'),str) and len(data['wordlist_path'])<=4096:
        result['wordlist_path']=data['wordlist_path']
    return result


def load():
    try:
        path=settings_path()
        if path.stat().st_size>65536:return {}
        return clean(json.loads(path.read_text()))
    except (OSError,ValueError):return {}


def save(data):
    path=settings_path();path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,prefix='.preferences-',delete=False) as stream:
            temporary=Path(stream.name)
            json.dump(clean(data),stream,indent=2);stream.write('\n')
        temporary.replace(path)
    finally:
        if temporary:temporary.unlink(missing_ok=True)
