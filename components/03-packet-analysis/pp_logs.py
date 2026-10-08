"""Bounded saved TShark field logs: file/line provenance, no live collection."""
from __future__ import annotations

import hashlib
import ipaddress
from collections import Counter
from decimal import Decimal, InvalidOperation
from pathlib import Path

from pp_evidence import MAX_BYTES, analyse_capture, preflight

VERSION = 'packetpilot-tshark-log-1.0'
MAX_RECORDS = 10_000
MAX_LINE_BYTES = 4096
FIELDS = ('frame.number', 'frame.time_epoch', 'frame.len', 'ip.src', 'ip.dst',
          'ip.proto', 'tcp.srcport', 'tcp.dstport', 'tcp.flags', 'udp.srcport', 'udp.dstport')
LAB = ipaddress.ip_network('10.77.0.0/24')
LIMITATIONS = [
    'Only the documented UTF-8 TShark field-log TSV format is accepted; not arbitrary text or Zeek logs.',
    'Rows are saved log observations, not raw packet bytes. Source frame numbers are exported identifiers, not independent packet verification.',
    'Only the exported IPv4 TCP/UDP fields are interpreted. Payload, checksums, reassembly, encryption and application content are unavailable.',
    'Malformed/unsupported rows remain counted and referenced, but their missing fields cannot support conclusions.',
    'The log does not establish capture completeness, authorisation, business impact or current network state. Uploaded logs cannot authorise execution.',
]


def _raw(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError('Saved evidence must be non-empty and no larger than 8 MiB.')
    return raw


def input_fingerprint(path):
    """Recheck retained source bytes before a question without selecting new data."""
    if Path(path).suffix.lower() == '.tsv':
        return {'sha256': hashlib.sha256(_raw(path)).hexdigest()}
    return preflight(path)


def analyse_input(path, decoder='auto'):
    suffix = Path(path).suffix.lower()
    if suffix == '.tsv':
        return analyse_log(path)
    if suffix == '.pcap':
        return analyse_capture(path, decoder)
    raise ValueError('Choose a classic .pcap or the documented TShark .tsv field log.')


def _integer(text, low, high):
    if not text.isascii() or not text.isdecimal():
        raise ValueError('Expected an unsigned integer field.')
    value = int(text)
    if not low <= value <= high:
        raise ValueError('Integer field out of range.')
    return value


def analyse_log(path):
    raw = _raw(path)
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        raise ValueError('The field log must be UTF-8 text.') from None
    if '\x00' in text or any(ord(c) < 32 and c not in '\t\r\n' for c in text):
        raise ValueError('Control/binary characters are not accepted in a field log.')
    lines = raw.splitlines(keepends=True)
    if any(len(line) > MAX_LINE_BYTES for line in lines):
        raise ValueError('A field-log line exceeds 4096 bytes.')
    if lines[0].rstrip(b'\r\n').decode('utf-8').split('\t') != list(FIELDS):
        raise ValueError('The TSV header must exactly match the documented TShark fields and order.')
    if not 1 <= len(lines)-1 <= MAX_RECORDS:
        raise ValueError('A field log must contain 1-10000 data rows.')
    digest = hashlib.sha256(raw).hexdigest()
    records, frames = [], set()
    offset = len(lines[0])
    for number, line in enumerate(lines[1:], 2):
        row = {'id': f'{digest}:l{number}', 'line_number': number,
               'byte_offset': offset, 'byte_length': len(line),
               'line_sha256': hashlib.sha256(line).hexdigest(),
               'status': 'malformed', 'source_frame_number': None, 'timestamp': None,
               'reported_frame_length': None, 'protocol': 'UNKNOWN', 'ipv4': None,
               'tcp': None, 'udp': None, 'reason': None}
        offset += len(line)
        values = line.rstrip(b'\r\n').decode('utf-8').split('\t')
        # Reject recognisable non-lab addresses even in otherwise malformed rows.
        if len(values) == len(FIELDS):
            for address in values[3:5]:
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if parsed not in LAB:
                    raise ValueError('Field logs must stay within the configured 10.77.0.0/24 lab.')
        try:
            if len(values) != len(FIELDS):
                raise ValueError('Wrong column count.')
            frame, stamp, length, source, destination, proto, ts, td, flags, us, ud = values
            frame_number = _integer(frame, 1, 2**31-1)
            if frame_number in frames:
                raise ValueError('Duplicate source frame number.')
            frames.add(frame_number)
            if len(stamp) > 120:
                raise ValueError('Timestamp field exceeds its bound.')
            when = Decimal(stamp)
            if not when.is_finite() or not 0 <= when <= Decimal('253402300799'):
                raise ValueError('Invalid timestamp.')
            row.update(source_frame_number=frame_number, timestamp=str(when),
                       reported_frame_length=_integer(length, 1, 16_777_216))
            if not source and not destination and not proto and not any((ts, td, flags, us, ud)):
                row.update(status='unsupported', protocol='NON_IPV4', reason='No exported IPv4 transport fields.')
            else:
                ip = {'src': str(ipaddress.IPv4Address(source)), 'dst': str(ipaddress.IPv4Address(destination))}
                protocol = _integer(proto, 0, 255)
                row.update(ipv4=ip, protocol={6: 'TCP', 17: 'UDP'}.get(protocol, 'OTHER'))
                if protocol == 6:
                    if us or ud or not flags.startswith('0x') or len(flags) > 6:
                        raise ValueError('Inconsistent TCP fields.')
                    bits = int(flags, 16)
                    if not 0 <= bits <= 511:
                        raise ValueError('Invalid TCP flags.')
                    row['tcp'] = {'src_port': _integer(ts, 0, 65535), 'dst_port': _integer(td, 0, 65535),
                                  'flags': bits, 'flag_names': [name for bit, name in
                                  ((1,'FIN'), (2,'SYN'), (4,'RST'), (8,'PSH'), (16,'ACK'), (32,'URG'), (64,'ECE'), (128,'CWR'), (256,'NS')) if bits & bit]}
                    row['status'] = 'decoded'
                elif protocol == 17:
                    if ts or td or flags:
                        raise ValueError('Inconsistent UDP fields.')
                    row['udp'] = {'src_port': _integer(us, 0, 65535), 'dst_port': _integer(ud, 0, 65535)}
                    row['status'] = 'decoded'
                else:
                    row.update(status='unsupported', reason='Exported transport protocol is not TCP or UDP.')
        except (ValueError, InvalidOperation, OverflowError):
            # Never put arbitrary source text or partially validated fields in model context.
            row.update(status='malformed', protocol='UNKNOWN', ipv4=None, tcp=None, udp=None,
                       reason='Invalid or missing required fields; raw line retained only in the source file.')
        records.append(row)
    counts = Counter(row['status'] for row in records)
    if not counts['decoded']:
        raise ValueError('No usable lab TCP/UDP rows were found in this field log.')
    good = [row for row in records if row['status'] == 'decoded']
    overview = {'record_count': len(records), 'protocol_counts': dict(sorted(Counter(r['protocol'] for r in good).items())),
                'first_timestamp': min(Decimal(r['timestamp']) for r in good).__str__(),
                'last_timestamp': max(Decimal(r['timestamp']) for r in good).__str__(),
                'endpoints': sorted({r['ipv4'][key] for r in good for key in ('src', 'dst')})}
    coverage = {'total_records': len(records), 'decoded_records': counts['decoded'],
                'malformed_records': counts['malformed'], 'unsupported_records': counts['unsupported'],
                'available_fields': list(FIELDS), 'unavailable': ['raw frames', 'payload', 'application content', 'capture completeness'],
                'decoded_packets': 0}
    return {'schema_version': '2', 'log_schema_version': '1.0', 'input_kind': 'network_log',
            'capture': {'sha256': digest, 'size_bytes': len(raw), 'format': 'tshark-fields-tsv',
                        'packet_count': 0, 'record_count': len(records)},
            'decoder': {'name': 'tshark-field-log-parser', 'version': VERSION},
            'log_records': records, 'packets': [], 'flows': [], 'coverage': coverage, 'overview': overview,
            'finding': 'insufficient_evidence', 'candidate_source': None, 'distinct_ports': [],
            'facts': [{'id': digest+':coverage', 'text': 'Saved log observations are available; no packet-rule verdict or model assessment was calculated.', 'packet_refs': []}],
            'legacy_assessment': {'purpose': 'Compatibility placeholder only; no TCP rule applied to log input.'},
            'limitations': list(LIMITATIONS)}
