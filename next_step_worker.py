"""Isolated AI request so emergency stop can interrupt it immediately."""
import json
import sys
from live_advice import recommendation

if __name__=='__main__':
    try:
        data=json.load(sys.stdin)
        print(json.dumps({'answer':recommendation(data['snapshot'],data['context'])}),flush=True)
    except Exception as exc:
        # API errors are sanitized by the client; never echo the submitted evidence or key.
        print(json.dumps({'error':str(exc) if isinstance(exc,RuntimeError) else 'AI review failed'}),flush=True)
