# Contributing to Watson

> *"It is not enough to have a good mind; the main thing is to use it well."*
> — Dr. J.H. Watson

Contributions are welcome. The most valuable thing you can add is a new technique — Watson's usefulness scales directly with the breadth of what it can examine.

---

## Adding a technique

Every technique is a Python class in `watson/techniques/`. Each one inherits `BaseTechnique` and implements two methods.

### 1. Create your file

Pick the right subdirectory:

```
watson/techniques/
  universal/    — runs on every file regardless of type
  images/       — PNG, JPEG, GIF, BMP, etc.
  audio/        — WAV, MP3, FLAC, etc.
  documents/    — PDF, Office formats
  containers/   — ZIP, TAR, and other archives
  disk/         — raw disk images, VMDK, VHD
```

If your technique doesn't fit any of these, add a new directory with an `__init__.py`.

### 2. Implement the class

```python
from __future__ import annotations

from pathlib import Path
from typing import List

from watson.techniques.base import BaseTechnique, Finding


class MyTechnique(BaseTechnique):
    name = "my_technique"
    description = "One sentence describing what this does."

    def applicable(self, path: Path, mime: str) -> bool:
        # Return True for the file types this technique handles.
        # Keep this cheap — no I/O here.
        return mime.startswith("image/")

    def examine(self, path: Path) -> List[Finding]:
        findings = []
        try:
            # Do the work here.
            # Use self._flag_pattern(text) to check for CTF flags.
            # Use self._find_all_flags(text) to get all matches.
            ...

            if something_interesting:
                findings.append(Finding(
                    technique=self.name,
                    message="Description of what was found",
                    confidence="MED",   # HIGH / MED / LOW
                ))

            if flag := self._flag_pattern(some_text):
                findings.append(Finding(
                    technique=self.name,
                    message=f"Flag found: {flag}",
                    confidence="HIGH",
                    flag=flag,
                ))

        except Exception:
            # Never let a broken technique crash Watson — just return nothing.
            pass

        return findings
```

### 3. Register it in the examiner

Open `watson/core/examiner.py` and add your technique to `_get_techniques()`:

```python
from watson.techniques.images.my_technique import MyTechnique

all_techniques: List[BaseTechnique] = [
    StringsScan(),
    EncodingDetect(),
    ...
    MyTechnique(),   # add here, in the right group
    ...
]
```

That's all — Watson picks it up automatically from there.

---

## Guidelines

**Techniques must never crash Watson.** Wrap your entire `examine()` body in `try/except`. A broken technique should silently return an empty list, not an exception.

**Don't import heavy dependencies at module level.** Use lazy imports inside `examine()` so Watson starts fast even if the dependency isn't installed:

```python
def examine(self, path: Path) -> List[Finding]:
    try:
        import some_heavy_lib
    except ImportError:
        return []
    ...
```

**Confidence levels:**
- `HIGH` — almost certainly relevant. Flag found, or data clearly hidden. Warrants immediate attention.
- `MED` — suspicious. Entropy anomaly, unusual metadata, something that doesn't fit. Worth investigating.
- `LOW` — informational. Base64 candidate, a URL, a string that might be relevant. Background noise the user can filter.

**Extracted files** — if your technique carves or extracts data, write it to a temp file and include it in `Finding.extracted_files`. Watson will automatically score and queue it for examination:

```python
import tempfile

tmp = Path(tempfile.mktemp(suffix=".bin"))
tmp.write_bytes(carved_data)

findings.append(Finding(
    technique=self.name,
    message="Carved embedded file at offset 0x1400",
    confidence="HIGH",
    extracted_files=[tmp],
))
```

**`applicable()` should be cheap.** It's called on every file for every technique. No file I/O — just check the MIME type or extension.

---

## Reporting bugs

Open an issue. Include:
- The command you ran
- Watson version (`watson --version`)
- What you expected vs what happened
- The output of `watson doctor`

If the file triggering the bug is shareable, attach it.

---

## Development setup

```bash
git clone https://github.com/Hum-Coder/WatsonCTF
cd WatsonCTF
python -m venv .venv && source .venv/bin/activate
pip install -e ".[full]"
watson doctor
```
