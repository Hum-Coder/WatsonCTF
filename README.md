# Watson

> *"I have made it a habit to observe first, conclude second."*
> — Dr. J.H. Watson

A forensics CTF solver for the command line. Watson takes a file — any file — and methodically applies a pipeline of forensics techniques to it, reporting findings as case notes. When something interesting is extracted, it examines that too, recursively, until the case is closed or the trail runs cold.

Named after Sherlock Holmes's indispensable assistant. Watson does the legwork so you can make the deductions.

```
$ watson examine suspicious.png

╔══[ CASE OPENED ]══════════════════════════════════════╗
║  Subject:  suspicious.png                             ║
║  Size:     84.2 KB                                    ║
║  Type:     image/png                                  ║
║                                                       ║
║  "I have always held that the world would be a        ║
║   better place if we observed more and assumed less." ║
║                              — Dr. J.H. Watson        ║
╚═══════════════════════════════════════════════════════╝

┌─[ strings_scan ]───────────────────────────────────────
  ○ LOW  strings_scan
       Base64-like strings found (2): e.g. aGVsbG8gd29ybGQ=

┌─[ appended_data ]──────────────────────────────────────
  ● HIGH  appended_data
       412 bytes appended after IEND chunk
       → Extracted: /tmp/watson_extract_x7k2/appended.bin

┌─[ Examining extracted file (depth 1): appended.bin ]───
  ● HIGH  strings_scan
       CTF flag pattern found: picoCTF{w4ts0n_w4s_r1ght}

╔══[ FLAG FOUND ]═══════════════════════════════════════╗
║  Good heavens — a flag!                               ║
║                                                       ║
║    picoCTF{w4ts0n_w4s_r1ght}                          ║
║                                                       ║
║  Discovered by: strings_scan                          ║
╚═══════════════════════════════════════════════════════╝
```

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Hum-Coder/WatsonCTF/main/install.sh | bash
```

That's it. The script will:
- Clone the repo to `~/.local/share/watson-ctf`
- Install the Python package and all core dependencies
- Detect your OS and install system tools (`binwalk`, `sleuthkit`, `steghide`, etc.)
- Run `watson doctor` so you can see exactly what's available

Re-running the command updates your installation.

**Requires:** Python 3.9+, git

---

## Usage

```bash
# Examine any file
watson examine suspicious.png
watson examine dump.dd
watson examine archive.zip

# Shorthand — no subcommand needed
watson suspicious.png

# Examine a whole directory
watson examine ./challenge_files/

# Keep extracted artifacts
watson examine file.bin --extract-dir ./artifacts/

# Go deeper, examine more files
watson examine file.bin --depth 5 --max-files 50

# Maximum effort
watson examine file.bin --aggressive

# Check what tools are installed
watson doctor
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--depth / -d` | `3` | Recursion depth for extracted files |
| `--max-files / -n` | `25` | Max files to examine before stopping |
| `--extract-dir / -o` | temp dir | Keep extracted files here |
| `--verbose / -v` | off | Show technique-level detail |
| `--aggressive / -a` | off | Sets depth=6, max-files=100 |
| `--modules / -m` | from config | Only use these modules, e.g. `core,images` |
| `--skip / -s` | none | Skip these modules for this run |

### Module management

```bash
watson modules list                  # show all modules and their status
watson modules enable disk           # enable for all future runs
watson modules disable audio         # disable for all future runs
watson modules install network       # show install commands for a module
```

Modules: `core` `images` `audio` `documents` `containers` `disk` `network`

`core` is always on and cannot be disabled. Default install enables `core`, `images`, and `containers`.

### Configuration

Watson stores its settings in `~/.config/watson/watson.cfg` — a plain text file you can edit directly.

```bash
watson config show                         # print all settings
watson config set core.default_depth 5    # set examine depth permanently
watson config set core.extract_dir ~/ctf/artifacts
watson config set flags.extra_patterns lactf\{[^}]+\},uiuctf\{[^}]+\}
watson config get core.default_depth       # read a single value
watson config reset                        # restore defaults
watson config path                         # print the config file location
```

Key settings:

| Key | Default | Description |
|-----|---------|-------------|
| `core.default_depth` | `3` | Default `--depth` |
| `core.default_max_files` | `25` | Default `--max-files` |
| `core.aggressive` | `false` | Always run in aggressive mode |
| `core.extract_dir` | *(temp)* | Always keep extracted files here |
| `core.verbose` | `false` | Always verbose |
| `output.theme` | `true` | Watson quotes and case notes framing |
| `output.color` | `true` | Rich colour output |
| `flags.extra_patterns` | *(empty)* | Extra flag regexes, comma-separated |

---

## What Watson examines

### Images
`.png` `.jpg` `.bmp` `.gif` `.tiff` `.webp`

- LSB steganography (per-channel entropy + ASCII extraction)
- EXIF metadata — GPS coordinates, UserComment, Software field
- Data appended after the logical end of the file (PNG IEND, JPEG EOI, GIF trailer)
- Palette manipulation

### Audio
`.wav` `.mp3` `.flac` `.ogg` `.aac`

- Sample-level LSB analysis
- Spectrogram generation (flags hidden in frequency domain)
- Audio metadata via `mutagen`

### Documents
`.pdf`

- Metadata and author fields
- Hidden annotations and optional content groups
- Embedded file attachments
- Full text extraction and flag scanning

### Archives & containers
`.zip` `.jar` `.apk` `.docx` `.xlsx`

- ZIP comment field (common CTF hiding spot)
- Password bruteforce against common CTF wordlist
- Full member extraction — all files fed back into the pipeline
- Nested archive handling

### Binaries & unknown files
Any file type

- Printable string extraction and flag pattern matching
- Encoding detection: base64, hex, rot13, URL encoding — decoded and re-checked
- Magic byte scanning for embedded files at non-zero offsets
- `binwalk` carving if available

### Cipher identification
Any file type

Watson identifies cipher types by statistical analysis — it won't break them, but it tells you what you're looking at and shows you the ciphertext.

- **RSA** — PEM blocks, SSH public keys, CTF-style `n/e/c` parameter dumps. Flags weak keys (small `n`, `e=3`, `p≈q`) with attack hints
- **Caesar / ROT-N** — frequency analysis picks the most likely shift, shows decoded text. If the shift produces a flag, it's reported immediately
- **Vigenère** — Index of Coincidence detection, Kasiski test estimates key length
- **Atbash** — reversed alphabet detection
- **Morse code** — character set detection, decoded inline
- **Bacon cipher** — A/B pattern detection, decoded inline
- **XOR** — entropy + Hamming distance key length estimation
- **AES-ECB** — high entropy + identical 16-byte blocks
- **Block ciphers** — high entropy + block-aligned length

### Network captures
`.pcap` `.pcapng` `.cap`

- Protocol breakdown and capture summary
- TCP stream reassembly — extracted streams fed back into the pipeline
- HTTP object extraction (files, images, documents transferred over HTTP)
- Plaintext credential detection (FTP, HTTP Basic Auth, form POST, SMTP, Telnet)
- DNS exfiltration detection — reconstructs and decodes data hidden in DNS queries

### Disk images
`.img` `.dd` `.raw` `.vmdk` `.vhd`

- MBR and GPT partition table parsing
- Per-partition filesystem walking
- Deleted file recovery via inode analysis (Sleuth Kit)
- Unallocated space entropy scan and file carving
- Common artifact locations: shell history, `/tmp/`, browser history, `/root/`
- VMDK/VHD converted to raw via `qemu-img` automatically

---

## How it works

Watson runs a **triage pipeline**: every file enters a priority queue, gets scored, and is examined with all applicable techniques. Files extracted by techniques (carved data, zip members, recovered deleted files) are pushed back into the queue and examined at the next depth level.

```
examine root file
  └─ run all applicable techniques
      └─ techniques extract files → scored and queued
          └─ examine extracted files
              └─ and so on, up to --depth
```

**Triage scoring** ensures the most suspicious files are always examined first:
- High entropy → higher priority
- Recognised types (image, zip, pdf) → bonus
- Filename contains `flag`, `secret`, `key` → large bonus
- Deeper in the tree → penalty

If Watson finds a flag at any depth, it's printed immediately in a prominent panel. At the end, any high/medium confidence non-flag findings are listed as **"Leads to Follow"** — an actionable list of what to investigate manually.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add new techniques.

---

## Optional tools

Watson degrades gracefully — it works without any of these, but installs them for full capability:

The install script supports: **Debian/Ubuntu/Kali** (`apt`), **Fedora/RHEL/Rocky/AlmaLinux** (`dnf`), **CentOS** (`yum`), **Arch/Manjaro/BlackArch** (`pacman`), **macOS** (`brew`). On RHEL-based distros it enables EPEL automatically for packages not in the base repos.

| Tool | Unlocks |
|------|---------|
| `binwalk` | Deep file carving from binaries |
| `foremost` | Unallocated space carving |
| `sleuthkit` (mmls/fls/icat) | Disk image + deleted file recovery |
| `steghide` | JPEG/BMP steganography extraction |
| `exiftool` | Extended EXIF and metadata |
| `qemu-img` | VMDK and VHD disk image support |
| `python-magic` | Accurate MIME type detection |
| `pytsk3` | Python bindings for Sleuth Kit |
| `scipy` / `numpy` | Spectrogram generation |
| `mutagen` | Audio metadata |
| `pypdf` | PDF text and structure analysis |
| `scapy` | PCAP stream reassembly, credential sniffing, DNS exfil detection |
| `tshark` | HTTP object extraction from packet captures |

Run `watson doctor` to see what's installed and what's missing.

---

## License

MIT — see [LICENSE](LICENSE).

> *"It is a capital mistake to theorise before one has data."*
