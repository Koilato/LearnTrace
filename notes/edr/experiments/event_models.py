"""Offline teaching models, not sensors, an OpenIOC engine, or an OS responder."""
import math
import xml.etree.ElementTree as ET


def masked_offsets(data, pattern, mask):
    """Small byte matcher. True mask positions must match; False is a wildcard."""
    if not pattern or len(pattern) != len(mask):
        raise ValueError('nonempty pattern and equal-sized mask required')
    return [i for i in range(len(data) - len(pattern) + 1)
            if all(not required or data[i + j] == pattern[j]
                   for j, required in enumerate(mask))]


def match_audit(xml_text):
    """Parse SMALL TRUSTED fixtures only. This is not OpenIOC XML syntax."""
    if len(xml_text) > 65536:
        raise ValueError('fixture too large')
    if '<!DOCTYPE' in xml_text.upper() or '<!ENTITY' in xml_text.upper():
        raise ValueError('DTD/entity declarations not accepted')
    root = ET.fromstring(xml_text)
    hits = {}
    for host in root.findall('host'):
        host_id = host.get('id')
        if not host_id or host_id in hits:
            raise ValueError('missing or duplicate host id')
        services = [s.get('name') for s in host.findall('service')
                    if s.get('name') == 'MS 1atent time services']
        files = []
        for f in host.findall('file'):
            size = int(f.attrib['size'])
            if size < 0:
                raise ValueError('negative file size')
            if f.get('name') == 'bad.exe' and 4096 <= size <= 10240:
                if not f.get('id'):
                    raise ValueError('file evidence id required')
                files.append(f.get('id'))
        hits[host_id] = {'match': bool(services or files),
                         'services': services, 'files': files}
    return hits


def process_key(event):
    fields = ('host', 'boot', 'pid', 'start')
    if any(k not in event or event[k] is None or event[k] == '' for k in fields):
        raise ValueError('complete process identity required')
    return tuple(event[k] for k in fields)


def detect_sequence(events, window=60.0, max_pending=10000):
    """One alert per qualifying start: creation -> network to port 443.

    Input must already be normalized and globally nondecreasing in event time.
    Unrelated events are skipped; exit clears a pending match. Inclusive window.
    Deduplication is by (host, boot, event_id); conflicting duplicates are errors.
    This finite offline model is not a general CEP/NFA implementation.
    """
    if not math.isfinite(window) or window < 0 or max_pending <= 0:
        raise ValueError('invalid limits')
    pending, seen, alerts = {}, {}, []
    last_time = -math.inf
    for event in events:
        key = process_key(event)
        t = event['time']
        if not isinstance(t, (int, float)) or not math.isfinite(t):
            raise ValueError('finite numeric event time required')
        if not event.get('id'):
            raise ValueError('event id required')
        eid = (event['host'], event['boot'], event['id'])
        if eid in seen:
            if event != seen[eid]:
                raise ValueError('conflicting event id')
            continue
        if t < last_time:
            raise ValueError('out-of-order input: reorder offline before calling')
        last_time = t
        seen[eid] = dict(event)
        pending = {k: e for k, e in pending.items() if t - e['time'] <= window}
        kind = event['kind']
        if (kind == 'process' and event.get('image', '').lower() == 'powershell.exe'
                and event.get('parent_image', '').lower() == 'winword.exe'):
            if key not in pending and len(pending) >= max_pending:
                raise ValueError('state budget exhausted; analysis incomplete')
            pending[key] = dict(event)
        elif kind == 'network' and event.get('port') == 443 and key in pending:
            first = pending.pop(key)
            alerts.append({'process': key, 'evidence': [first['id'], event['id']],
                           'verdict': 'NEEDS_REVIEW'})
        elif kind == 'exit':
            pending.pop(key, None)
    return alerts


def resolve_process(host, boot, pid, event_time, lifetimes):
    matches = [p for p in lifetimes
               if (p['host'], p['boot'], p['pid']) == (host, boot, pid)
               and p['start'] <= event_time
               and (p['end'] is None or event_time < p['end'])]
    return matches[0]['instance'] if len(matches) == 1 else None


def response_step(state, event):
    """Simulation only. No network changes. Caller must validate task/device binding.

    'verify' means separately supplied effective-policy evidence, not an ACK.
    Failed/verified are terminal for this task; retries require a new task id.
    """
    transitions = {
        'queued': {'accepted': 'accepted', 'timeout': 'unknown', 'failed': 'failed'},
        'accepted': {'applied': 'reported', 'timeout': 'unknown', 'failed': 'failed'},
        'reported': {'verify': 'verified', 'timeout': 'unknown', 'failed': 'failed'},
        'unknown': {'accepted': 'accepted', 'applied': 'reported', 'failed': 'failed'},
        'failed': {}, 'verified': {}
    }
    if state not in transitions:
        raise ValueError('unknown task state')
    return transitions[state].get(event, state)
