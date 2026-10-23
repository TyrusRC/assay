"""assay IAST sensor for Python.

Deploy: set PYTHONSTARTUP=/path/to/sensor.py or copy as sitecustomize.py.
Set ASSAY_CALLBACK_URL to the assay IAST server.
"""

import os, json, traceback, urllib.request
from datetime import datetime

CALLBACK = os.environ.get('ASSAY_CALLBACK_URL', 'http://host.docker.internal:7880/api/v1/sink')
PREFIX = 'ASSAY_TAINT_'
SUFFIX = '_TAINT_ASSAY'

def _check(value, sink_type):
    s = str(value)
    if PREFIX not in s or SUFFIX not in s:
        return
    import re
    m = re.search(r'ASSAY_TAINT_([a-f0-9]{8})_', s)
    marker_id = m.group(1) if m else ''
    stack = ' -> '.join(f'{f.filename}:{f.lineno}' for f in traceback.extract_stack()[-5:])
    data = json.dumps({
        'marker_id': marker_id, 'sink_type': sink_type,
        'sink_value': s[:500], 'stack_trace': stack,
        'timestamp': datetime.utcnow().isoformat(),
    }).encode()
    try:
        req = urllib.request.Request(CALLBACK, data=data,
            headers={'Content-Type': 'application/json'}, method='POST')
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass

# Hook sqlite3
try:
    import sqlite3
    _orig_execute = sqlite3.Cursor.execute
    def _hooked_execute(self, sql, *a, **kw):
        _check(sql, 'sql_query')
        return _orig_execute(self, sql, *a, **kw)
    sqlite3.Cursor.execute = _hooked_execute
except ImportError:
    pass

# Hook subprocess
try:
    import subprocess
    _orig_run = subprocess.run
    def _hooked_run(args, *a, **kw):
        if isinstance(args, str):
            _check(args, 'sys_command')
        elif isinstance(args, (list, tuple)) and args:
            _check(' '.join(str(x) for x in args), 'sys_command')
        return _orig_run(args, *a, **kw)
    subprocess.run = _hooked_run
except ImportError:
    pass

# Hook os.system
_orig_system = os.system
def _hooked_system(cmd):
    _check(cmd, 'sys_command')
    return _orig_system(cmd)
os.system = _hooked_system
