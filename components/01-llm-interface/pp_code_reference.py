"""Reviewed read-only example source. It is not automatically executed by a model."""
import hashlib

VERSION='packetpilot-code-reference-1.2'
TSV_CHECKER='''import ipaddress
import json
import sys
from decimal import Decimal, InvalidOperation

FIELDS = "frame.number frame.time_epoch frame.len ip.src ip.dst ip.proto tcp.srcport tcp.dstport tcp.flags udp.srcport udp.dstport".split()
LAB = ipaddress.ip_network("10.77.0.0/24")

def uint(text, maximum, minimum=0):
    if not text.isascii() or not text.isdecimal():
        raise ValueError("unsigned integer required")
    value = int(text)
    if not minimum <= value <= maximum:
        raise ValueError("integer outside range")
    return value

def check(path):
    # Binary lines preserve CRLF/LF and count blank physical records.
    with open(path, "rb") as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    if not raw or len(raw) > 8 * 1024 * 1024:
        raise ValueError("file must be nonempty and at most 8 MiB")
    text = raw.decode("utf-8", errors="strict")
    if any(ord(c) < 32 and c not in "\\t\\r\\n" for c in text):
        raise ValueError("binary/control character")
    lines = raw.splitlines(keepends=True)
    if any(len(line) > 4096 for line in lines):
        raise ValueError("line exceeds 4096 bytes")
    if lines[0].rstrip(b"\\r\\n").decode("utf-8").split("\\t") != FIELDS:
        raise ValueError("header fields/order differ from supported TSV")
    if not 1 <= len(lines) - 1 <= 10000:
        raise ValueError("expected 1-10000 physical data lines")
    rows, seen = [], set()
    for number, line in enumerate(lines[1:], 2):
        status, reason = "malformed", None
        try:
            cells = line.rstrip(b"\\r\\n").decode("utf-8").split("\\t")
            if len(cells) != len(FIELDS):
                raise ValueError("wrong column count")
            frame, stamp, length, src, dst, proto, ts, td, flags, us, ud = cells
            frame_id = uint(frame, 2**31 - 1, 1)
            if frame_id in seen:
                raise ValueError("duplicate exported frame number")
            seen.add(frame_id)
            when = Decimal(stamp)
            if len(stamp) > 120 or not when.is_finite() or not 0 <= when <= Decimal("253402300799"):
                raise ValueError("invalid timestamp")
            uint(length, 16777216, 1)
            if not any((src, dst, proto, ts, td, flags, us, ud)):
                status = "unsupported"
            else:
                if ipaddress.IPv4Address(src) not in LAB or ipaddress.IPv4Address(dst) not in LAB:
                    raise ValueError("address outside lab")
                protocol = uint(proto, 255)
                if protocol == 6:
                    if us or ud or not flags.startswith("0x") or len(flags) > 6:
                        raise ValueError("inconsistent TCP fields")
                    uint(ts, 65535); uint(td, 65535)
                    if not 0 <= int(flags, 16) <= 511:
                        raise ValueError("invalid TCP flags")
                    status = "usable"
                elif protocol == 17:
                    if ts or td or flags:
                        raise ValueError("inconsistent UDP fields")
                    uint(us, 65535); uint(ud, 65535)
                    status = "usable"
                else:
                    status = "unsupported"
        except (ValueError, InvalidOperation, OverflowError):
            reason = "required/type/range/protocol fields failed"
        rows.append({"physical_line": number, "status": status, "reason": reason})
    return {"data_lines": len(rows), "usable": sum(r["status"] == "usable" for r in rows),
            "malformed": sum(r["status"] == "malformed" for r in rows),
            "unsupported": sum(r["status"] == "unsupported" for r in rows), "rows": rows}

if __name__ == "__main__":
    try:
        print(json.dumps(check(sys.argv[1])))
    except (ValueError, UnicodeError, OSError, IndexError) as error:
        print(json.dumps({"error": type(error).__name__})); sys.exit(2)
'''

def code_reference(topic):
    if topic!='tsv_checker':raise ValueError('Unknown reviewed code topic.')
    return {'kind':'reviewed_code_reference','topic':topic,'version':VERSION,
            'sha256':hashlib.sha256(TSV_CHECKER.encode()).hexdigest(),'language':'python','code':TSV_CHECKER,
            'port_min':0,'port_max':65535,'max_file_bytes':8388608,'max_line_bytes':4096,'max_data_lines':10000,
            'scope':'Standalone read-only checker for the exact PacketPilot eleven-column lab TSV; reports physical lines, not packet truth.',
            'execution_on_provision':'none',
            'execution_if_operator_runs':'Python executes the checker: reads input, prints JSON; no network or file modification.',
            'file_error_policy':'Bad encoding/control/header/order/size/line/record bounds raise a file-level error.',
            'row_error_policy':'Bad column/type/range/duplicate/transport fields mark that row malformed and continue.',
            'duplicate_frame_policy':'report_malformed_row_continue',
            'production_duplicate_frame_policy':'report_malformed_row_continue',
            'outside_lab_policy':'report_malformed_row_continue',
            'production_outside_lab_policy':'reject_whole_file',
            'unsupported_policy':'Common fields pass; ALL IPv4 and transport cells blank, or valid lab IPv4 with other numeric protocol.',
            'provenance_policy':'Physical line counting, not byte offsets/per-row hashes; not the production importer.',
            'limitations':'No PCAP decoding or application-success proof; not a replacement for production provenance/hash import. Outside-lab rows are marked malformed here; the production importer rejects the whole file. No command is executed by providing this reference.'}
