"""Synthetic identity marker, not a detector or a scored boundary monitor."""

import json
import os
import signal
import sys

signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
score = float(os.environ['PROBE_SCORE'])
for line in sys.stdin:
    request = json.loads(line)
    response = {key: request[key] for key in ('protocol', 'request_id')}
    if request['protocol'] == 'lurebench-detector-v1':
        response['score'] = score
    else:
        response['alerts'] = [] if score == 0.125 else [{'changed': True}]
    print(json.dumps(response), flush=True)
