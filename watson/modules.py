"""
Watson module registry.

Defines available forensics modules and their associated techniques,
Python dependencies, and system dependencies.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Module:
    """A Watson forensics module grouping related techniques and dependencies."""

    name: str
    description: str
    techniques: List[str] = field(default_factory=list)
    python_deps: Dict[str, str] = field(default_factory=dict)
    system_deps: List[str] = field(default_factory=list)
    apt_pkgs: List[str] = field(default_factory=list)
    dnf_pkgs: List[str] = field(default_factory=list)
    pacman_pkgs: List[str] = field(default_factory=list)
    brew_pkgs: List[str] = field(default_factory=list)
    always_on: bool = False

    def is_available(self) -> bool:
        """True if all python_deps are importable AND all system_deps are in PATH."""
        if self.always_on:
            return True
        for import_name in self.python_deps:
            try:
                __import__(import_name)
            except ImportError:
                return False
        for tool in self.system_deps:
            if shutil.which(tool) is None:
                return False
        return True

    def missing_python(self) -> List[str]:
        """Return pip packages that are not installed."""
        missing = []
        for import_name, pip_pkg in self.python_deps.items():
            try:
                __import__(import_name)
            except ImportError:
                missing.append(pip_pkg)
        return missing

    def missing_system(self) -> List[str]:
        """Return system tools that are not in PATH."""
        return [tool for tool in self.system_deps if shutil.which(tool) is None]

    def install_cmd(self, os_type: str) -> List[str]:
        """Return list of packages to install for the given os_type."""
        os_type = os_type.lower()
        if os_type in ("apt", "apt-get"):
            return list(self.apt_pkgs)
        elif os_type in ("dnf", "yum"):
            return list(self.dnf_pkgs)
        elif os_type == "pacman":
            return list(self.pacman_pkgs)
        elif os_type == "brew":
            return list(self.brew_pkgs)
        return []


MODULES: Dict[str, Module] = {
    "core": Module(
        name="core",
        description="Universal techniques — strings, encoding detection",
        techniques=["StringsScan", "EncodingDetect"],
        python_deps={"magic": "python-magic"},
        system_deps=[],
        apt_pkgs=[],
        dnf_pkgs=[],
        pacman_pkgs=[],
        brew_pkgs=[],
        always_on=True,
    ),
    "images": Module(
        name="images",
        description="PNG, JPEG, GIF, BMP steganography and metadata",
        techniques=["ImageMetadata", "LSBDetect", "AppendedData"],
        python_deps={"PIL": "Pillow"},
        system_deps=[],
        apt_pkgs=[],
        dnf_pkgs=[],
        pacman_pkgs=[],
        brew_pkgs=[],
        always_on=False,
    ),
    "audio": Module(
        name="audio",
        description="WAV, MP3, FLAC spectrogram and audio metadata",
        techniques=["AudioSpectrogram"],
        python_deps={"mutagen": "mutagen", "scipy": "scipy", "numpy": "numpy"},
        system_deps=[],
        apt_pkgs=[],
        dnf_pkgs=[],
        pacman_pkgs=[],
        brew_pkgs=[],
        always_on=False,
    ),
    "documents": Module(
        name="documents",
        description="PDF analysis and text extraction",
        techniques=["PDFMeta"],
        python_deps={"pypdf": "pypdf"},
        system_deps=["pdfinfo"],
        apt_pkgs=["poppler-utils"],
        dnf_pkgs=["poppler-utils"],
        pacman_pkgs=["poppler"],
        brew_pkgs=["poppler"],
        always_on=False,
    ),
    "containers": Module(
        name="containers",
        description="ZIP extraction and binary carving",
        techniques=["ZipExtract", "BinwalkWrap"],
        python_deps={},
        system_deps=["binwalk"],
        apt_pkgs=["binwalk"],
        dnf_pkgs=["binwalk"],
        pacman_pkgs=["binwalk"],
        brew_pkgs=["binwalk"],
        always_on=False,
    ),
    "disk": Module(
        name="disk",
        description="Disk image forensics, partition and filesystem analysis, deleted file recovery",
        techniques=["PartitionAnalysis", "FilesystemAnalysis"],
        python_deps={"pytsk3": "pytsk3"},
        system_deps=["mmls", "fls", "icat", "qemu-img"],
        apt_pkgs=["sleuthkit", "qemu-utils"],
        dnf_pkgs=["sleuthkit", "qemu-img"],
        pacman_pkgs=["sleuthkit", "qemu"],
        brew_pkgs=["sleuthkit", "qemu"],
        always_on=False,
    ),
    "network": Module(
        name="network",
        description="PCAP and network capture analysis",
        techniques=["PcapMeta", "StreamReassembly", "HttpObjects", "CredentialSniffer", "DnsExfil"],
        python_deps={"scapy": "scapy"},
        system_deps=["tshark"],
        apt_pkgs=["tshark"],
        dnf_pkgs=["wireshark-cli"],
        pacman_pkgs=["wireshark-cli"],
        brew_pkgs=["wireshark"],
        always_on=False,
    ),
}


def get_techniques_for_modules(enabled: List[str]) -> List[str]:
    """Return flat list of technique class names for the given enabled module names."""
    result: List[str] = []
    for name in enabled:
        module = MODULES.get(name)
        if module is not None:
            for tech in module.techniques:
                if tech not in result:
                    result.append(tech)
    return result
