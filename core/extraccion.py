"""Typed entity extraction from free text -- F14 step 161.

Paste an article/dump and typed entities come out for the graph. Done with REGEX
(deterministic, no AI hallucinations -- important to avoid injecting false
positives), with an anti-FP filter for domains (don't mistake file names for domains).

PURE module."""
from __future__ import annotations
import re

# common extensions that are NOT domains (anti false-positive)
_NO_TLD = {'txt', 'jpg', 'jpeg', 'png', 'gif', 'pdf', 'html', 'htm', 'js', 'css',
          'py', 'exe', 'zip', 'doc', 'docx', 'xml', 'json', 'csv', 'md', 'php'}

_RX = [
    ('email', re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')),
    ('url', re.compile(r'https?://[^\s"\'<>]+')),
    ('wallet', re.compile(r'\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b')),
    ('ip', re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
    ('dominio', re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b', re.I)),
]


def extract_entities(texto: str) -> list:
    """Returns [(type, value), ...] without duplicates. Domains that are clearly
    file names (known extension) are discarded."""
    texto = texto or ''
    out, vistos = [], set()
    for type, rx in _RX:
        for m in rx.findall(texto):
            v = m.strip().rstrip('.,);:')
            if type == 'ip':
                if any(int(o) > 255 for o in v.split('.')):
                    continue                     # invalid octet
            if type == 'dominio' and v.rsplit('.', 1)[-1].lower() in _NO_TLD:
                continue                         # it's a file, not a domain
            key = (type, v.lower())
            if v and key not in vistos:
                vistos.add(key)
                out.append((type, v))
    return out
