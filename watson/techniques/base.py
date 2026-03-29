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
        patterns = [
            r'picoCTF\{[^\}]{1,100}\}',
            r'HTB\{[^\}]{1,100}\}',
            r'htb\{[^\}]{1,100}\}',
            r'flag\{[^\}]{1,100}\}',
            r'FLAG\{[^\}]{1,100}\}',
            r'CTF\{[^\}]{1,100}\}',
            r'ctf\{[^\}]{1,100}\}',
            r'[A-Za-z0-9_]{2,10}\{[^\}\s]{3,80}\}',
        ]
        for p in patterns:
            m = re.search(p, data)
            if m:
                return m.group(0)
        return None

    def _find_all_flags(self, data: str) -> List[str]:
        """Find all CTF flag patterns in a string."""
        patterns = [
            r'picoCTF\{[^\}]{1,100}\}',
            r'HTB\{[^\}]{1,100}\}',
            r'htb\{[^\}]{1,100}\}',
            r'flag\{[^\}]{1,100}\}',
            r'FLAG\{[^\}]{1,100}\}',
            r'CTF\{[^\}]{1,100}\}',
            r'ctf\{[^\}]{1,100}\}',
            r'[A-Za-z0-9_]{2,10}\{[^\}\s]{3,80}\}',
        ]
        found = []
        seen = set()
        for p in patterns:
            for m in re.finditer(p, data):
                val = m.group(0)
                if val not in seen:
                    seen.add(val)
                    found.append(val)
        return found
