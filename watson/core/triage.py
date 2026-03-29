"""
Watson Triage System — prioritises extracted files for recursive analysis.
"""
from __future__ import annotations

import heapq
import hashlib
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class WorkItem:
    path: Path
    depth: int
    score: float
    parent_technique: Optional[str] = None

    def __lt__(self, other: "WorkItem") -> bool:
        # max-heap: higher score = higher priority
        return self.score > other.score


class TriageQueue:
    """Priority queue for recursive file analysis."""

    # MIME / extension groups that get a bonus
    _INTERESTING_TYPES = {
        "image/", "application/zip", "application/x-zip",
        "application/pdf", "audio/", "application/x-tar",
        "application/gzip", "application/x-7z",
        "application/x-rar", "application/octet-stream",
    }
    _INTERESTING_NAMES = {"flag", "secret", "hidden", "key", "password", "creds"}

    def __init__(self, max_depth: int = 3, max_items: int = 25) -> None:
        self.max_depth = max_depth
        self.max_items = max_items
        self._heap: list[WorkItem] = []
        self._seen: set[str] = set()
        self._total_processed: int = 0

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_file(self, path: Path, depth: int) -> float:
        """Score a file for triage priority (higher = examine sooner)."""
        score = 0.0

        # Entropy-based score from first 4 KB
        try:
            data = path.read_bytes()[:4096]
            if data:
                score += self._entropy(data)  # 0–8
        except OSError:
            pass

        # Type bonus
        try:
            import magic  # type: ignore
            mime = magic.from_file(str(path), mime=True)
            for t in self._INTERESTING_TYPES:
                if mime.startswith(t):
                    score += 3
                    break
        except Exception:
            # Fallback: extension-based
            ext = path.suffix.lower()
            if ext in {".zip", ".png", ".jpg", ".jpeg", ".pdf", ".mp3", ".wav", ".gif", ".tar", ".gz"}:
                score += 3

        # Name bonus
        name_lower = path.stem.lower()
        for keyword in self._INTERESTING_NAMES:
            if keyword in name_lower:
                score += 5
                break

        # Depth penalty
        score -= 2 * depth

        return score

    @staticmethod
    def _entropy(data: bytes) -> float:
        """Shannon entropy (0–8) of byte data."""
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    # ------------------------------------------------------------------
    # Queue operations
    # ------------------------------------------------------------------

    def push(
        self,
        path: Path,
        depth: int,
        parent_technique: Optional[str] = None,
    ) -> bool:
        """Add a file to the triage queue. Returns False if skipped."""
        # Depth guard
        if depth > self.max_depth:
            return False

        # Size guard (500 MB)
        try:
            if path.stat().st_size > 500 * 1024 * 1024:
                return False
        except OSError:
            return False

        # Already-seen guard (by SHA-256 of first 64 KB)
        file_hash = self._quick_hash(path)
        if file_hash in self._seen:
            return False
        self._seen.add(file_hash)

        # Cap guard — once we've processed max_items, only root items (depth 0) get in
        if self._total_processed >= self.max_items and depth > 0:
            return False

        score = self.score_file(path, depth)
        item = WorkItem(path=path, depth=depth, score=score, parent_technique=parent_technique)
        heapq.heappush(self._heap, item)
        return True

    def pop(self) -> Optional[WorkItem]:
        """Return the highest-priority item, or None if queue is empty."""
        if not self._heap:
            return None
        item = heapq.heappop(self._heap)
        self._total_processed += 1
        return item

    def exhausted(self) -> bool:
        """Return True when there is nothing left to examine."""
        return len(self._heap) == 0

    def __len__(self) -> int:
        return len(self._heap)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _quick_hash(path: Path) -> str:
        """SHA-256 of first 64 KB — fast deduplication."""
        h = hashlib.sha256()
        try:
            with path.open("rb") as fh:
                h.update(fh.read(65536))
        except OSError:
            h.update(str(path).encode())
        return h.hexdigest()
