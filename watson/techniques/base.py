"""
Base technique interface and Finding dataclass.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class Finding:
    technique: str
    message: str
    confidence: str  # HIGH / MED / LOW
    extracted_files: List[Path] = field(default_factory=list)
    flag: Optional[str] = None  # if a CTF flag was found


class BaseTechnique(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    def applicable(self, path: Path, mime: str) -> bool:
        """Return True if this technique applies to the given file."""
        ...

    @abstractmethod
    def examine(self, path: Path) -> List[Finding]:
        """Run the technique and return findings."""
        ...

    def _flag_pattern(self, data: str) -> Optional[str]:
        """Search for CTF flag patterns in a string."""
        # Tier 1: known competition prefixes — high confidence, always match
        known = [
            r'picoCTF\{[^\}]{1,100}\}',
            r'HTB\{[^\}]{1,100}\}',
            r'htb\{[^\}]{1,100}\}',
            r'flag\{[^\}]{1,100}\}',
            r'FLAG\{[^\}]{1,100}\}',
            r'CTF\{[^\}]{1,100}\}',
            r'ctf\{[^\}]{1,100}\}',
            r'DUCTF\{[^\}]{1,100}\}',
            r'lactf\{[^\}]{1,100}\}',
            r'uiuctf\{[^\}]{1,100}\}',
            r'ictf\{[^\}]{1,100}\}',
        ]
        for p in known:
            m = re.search(p, data, re.IGNORECASE)
            if m:
                return m.group(0)

        # Tier 2: generic WORD{content} — much stricter to avoid JSON/CSS/code
        # Requirements: ALL-CAPS prefix, content has no spaces/colons/semicolons,
        # content contains at least one digit or underscore (flags rarely pure words)
        m = re.search(r'\b([A-Z]{2,10})\{([A-Za-z0-9_\-!@#$%^&*]{4,60})\}', data)
        if m:
            content = m.group(2)
            # Must have at least one digit or underscore — pure words are not flags
            if re.search(r'[\d_]', content):
                return m.group(0)

        return None

    def _find_all_flags(self, data: str) -> List[str]:
        """Find all CTF flag patterns in a string."""
        known = [
            r'picoCTF\{[^\}]{1,100}\}',
            r'HTB\{[^\}]{1,100}\}',
            r'htb\{[^\}]{1,100}\}',
            r'flag\{[^\}]{1,100}\}',
            r'FLAG\{[^\}]{1,100}\}',
            r'CTF\{[^\}]{1,100}\}',
            r'ctf\{[^\}]{1,100}\}',
            r'DUCTF\{[^\}]{1,100}\}',
            r'lactf\{[^\}]{1,100}\}',
            r'uiuctf\{[^\}]{1,100}\}',
            r'ictf\{[^\}]{1,100}\}',
        ]
        found = []
        seen = set()
        for p in known:
            for m in re.finditer(p, data, re.IGNORECASE):
                val = m.group(0)
                if val not in seen:
                    seen.add(val)
                    found.append(val)

        # Generic tier — same strict rules as _flag_pattern
        for m in re.finditer(r'\b([A-Z]{2,10})\{([A-Za-z0-9_\-!@#$%^&*]{4,60})\}', data):
            content = m.group(2)
            if re.search(r'[\d_]', content):
                val = m.group(0)
                if val not in seen:
                    seen.add(val)
                    found.append(val)

        return found
