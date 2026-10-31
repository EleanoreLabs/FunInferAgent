#!/usr/bin/env python3
"""Recover the function names rename.py computed but failed to apply.

rename.py's prompt example `{"old_name": "new_name"}` is ambiguous, so
qwen2.5-coder:32b-instruct returns the literal-key form
`{"old_name": "sub_X", "new_name": "Y"}` for ~96% of functions.
rename_to_ida only calls set_name when the real old name is a dict KEY
(`{"sub_X": "Y"}`), so the literal-key form is silently skipped and those
functions stay sub_.

This script parses rename.py's log.txt and recovers BOTH forms, using the
authoritative `Processing 0xADDR` line for the address (it IS the function
start_ea, since BFS seeds from idautils.Functions()) and the dict's new-name
value. To match rename.py's design (only rename auto-generated `sub_` names,
preserving real symbol names like `write`/`main`/`__cxa_finalize`), we keep
only entries whose old name starts with `sub_`.

Usage: parse_rename_log.py [log.txt] [out_map.json]
"""
import ast
import json
import re
import sys

if len(sys.argv) < 2:
    sys.exit("usage: parse_rename_log.py <log.txt> [out.json]")
LOG = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else (LOG[:-len('.log.txt')] + '.recover_map.json')

PROC_RE = re.compile(r'^Processing 0x([0-9a-fA-F]+)\s*$')

name_map = {}  # addr(int) -> new_name
stats = {'form_a_sub': 0, 'form_a_named': 0, 'form_b_sub': 0,
         'form_b_named': 0, 'no_rename': 0, 'weird': 0}
skipped_named = []

with open(LOG) as f:
    lines = [ln.rstrip('\n') for ln in f]

cur_addr = None
decided = False  # have we seen the deciding first dict for cur_addr?

for line in lines:
    m = PROC_RE.match(line)
    if m:
        cur_addr = int(m.group(1), 16)
        decided = False
        continue
    if line.startswith('Processing layer'):
        cur_addr = None
        decided = True
        continue
    if cur_addr is None or decided:
        continue
    if not line.startswith('{'):
        continue  # skip [Truncated], Attempt errors, blank, etc.
    try:
        d = ast.literal_eval(line)
    except Exception:
        continue  # unparseable dict line; keep scanning for the real first dict
    if not isinstance(d, dict):
        decided = True
        continue
    decided = True  # this first parseable dict decides this function
    if 'summary' in d:
        stats['no_rename'] += 1  # query_name returned nothing (e.g. JSON error)
        continue
    # rename dict
    if 'old_name' in d and 'new_name' in d:
        old, new = d['old_name'], d['new_name']
        bucket = 'form_b_sub' if str(old).startswith('sub_') else 'form_b_named'
    elif len(d) == 1:
        old, new = next(iter(d.items()))
        bucket = 'form_a_sub' if str(old).startswith('sub_') else 'form_a_named'
    else:
        old, new, bucket = None, None, 'weird'
    stats[bucket] += 1
    if str(old).startswith('sub_') and new:
        name_map[cur_addr] = new
    elif bucket in ('form_a_named', 'form_b_named'):
        skipped_named.append((hex(cur_addr), old, new))

with open(OUT, 'w') as f:
    json.dump({hex(a): n for a, n in name_map.items()}, f, indent=1)

print('=== parse_rename_log summary ===')
for k, v in stats.items():
    print('  %-12s %d' % (k, v))
print('  -> recovered (sub_ old-name) in map: %d' % len(name_map))
print('  -> map written: %s' % OUT)
print('  non-sub_ kept as original name (%d):' % len(skipped_named))
for t in skipped_named[:20]:
    print('    ', t)
print('  spot-check (addr -> recovered name):')
for a in [0xDD30, 0xDD60, 0xDE20, 0xE8F0, 0x4EEA0, 0x501A0, 0x43550, 0xE900]:
    print('    %s -> %s' % (hex(a), name_map.get(a, '<not in map>')))
