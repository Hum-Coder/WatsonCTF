"""
Audio spectrogram and metadata technique.
Uses scipy/numpy for spectrogram generation, mutagen for metadata.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import List

from watson.techniques.base import BaseTechnique, Finding

_AUDIO_MIMES = {
    "audio/mpeg", "audio/mp3", "audio/wav", "audio/x-wav",
    "audio/ogg", "audio/flac", "audio/x-flac", "audio/aac",
    "audio/mp4", "audio/x-m4a", "audio/vorbis",
}


class AudioSpectrogram(BaseTechnique):
    name = "audio_spectrogram"
    description = "Analyse audio files: spectrogram generation, metadata, and LSB in sample data."

    def applicable(self, path: Path, mime: str) -> bool:
        return mime in _AUDIO_MIMES or mime.startswith("audio/")

    def examine(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []

        # --- Mutagen metadata ---
        findings.extend(self._check_metadata(path))

        # --- Spectrogram ---
        spec_findings, spec_image = self._generate_spectrogram(path)
        findings.extend(spec_findings)

        # --- LSB in samples (WAV only, pure Python) ---
        if path.suffix.lower() == ".wav":
            findings.extend(self._wav_lsb(path))

        return findings

    # ------------------------------------------------------------------
    # Metadata via mutagen
    # ------------------------------------------------------------------

    def _check_metadata(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            import mutagen  # type: ignore
            from mutagen import File as MutaFile
        except ImportError:
            findings.append(Finding(
                technique=self.name,
                message="mutagen not available — audio metadata analysis limited.",
                confidence="LOW",
            ))
            return findings

        try:
            audio = MutaFile(str(path))
            if audio is None:
                return findings

            tags = dict(audio.tags) if audio.tags else {}
            for key, value in tags.items():
                val_str = str(value)[:200]
                flag = self._flag_pattern(val_str)
                if flag:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Flag found in audio tag '{key}': {val_str[:120]}",
                        confidence="HIGH",
                        flag=flag,
                    ))
                elif key.lower() in {"comment", "description", "lyrics", "unsyncedlyrics", "comm"}:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Audio tag [{key}]: {val_str[:100]}",
                        confidence="MED",
                    ))

            # Basic audio info
            info = audio.info
            if hasattr(info, "length"):
                duration = info.length
                findings.append(Finding(
                    technique=self.name,
                    message=f"Audio duration: {duration:.1f}s, format: {type(audio).__name__}",
                    confidence="LOW",
                ))

        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"mutagen error: {e}",
                confidence="LOW",
            ))

        return findings

    # ------------------------------------------------------------------
    # Spectrogram
    # ------------------------------------------------------------------

    def _generate_spectrogram(self, path: Path) -> tuple[List[Finding], Path | None]:
        """Generate a spectrogram image. Returns (findings, image_path or None)."""
        findings: List[Finding] = []
        try:
            import numpy as np  # type: ignore
            import scipy.io.wavfile as wavfile  # type: ignore
            import scipy.signal as signal  # type: ignore
        except ImportError:
            findings.append(Finding(
                technique=self.name,
                message="scipy/numpy not available — spectrogram generation skipped. Install: pip install scipy numpy",
                confidence="LOW",
            ))
            return findings, None

        # Only WAV files can be read directly; others need conversion
        wav_path = path
        converted = False
        if path.suffix.lower() != ".wav":
            wav_path, converted, err = self._convert_to_wav(path)
            if err:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Could not convert audio for spectrogram: {err}",
                    confidence="LOW",
                ))
                return findings, None

        try:
            sample_rate, data = wavfile.read(str(wav_path))
            if data.ndim > 1:
                data = data[:, 0]  # mono

            # Generate spectrogram
            f, t, Sxx = signal.spectrogram(data, fs=sample_rate, nperseg=512)

            # Save spectrogram image
            try:
                import matplotlib  # type: ignore
                matplotlib.use("Agg")
                import matplotlib.pyplot as plt  # type: ignore

                tmp_dir = tempfile.mkdtemp(prefix="watson_spec_")
                spec_path = Path(tmp_dir) / f"{path.stem}_spectrogram.png"

                fig, ax = plt.subplots(figsize=(12, 6))
                ax.pcolormesh(t, f, 10 * np.log10(Sxx + 1e-10), shading="gouraud", cmap="inferno")
                ax.set_ylabel("Frequency [Hz]")
                ax.set_xlabel("Time [sec]")
                ax.set_title(f"Spectrogram: {path.name}")
                plt.tight_layout()
                plt.savefig(str(spec_path), dpi=150)
                plt.close(fig)

                findings.append(Finding(
                    technique=self.name,
                    message=f"Spectrogram generated — inspect visually for hidden images/text (common CTF technique).",
                    confidence="MED",
                    extracted_files=[spec_path],
                ))
                return findings, spec_path

            except ImportError:
                findings.append(Finding(
                    technique=self.name,
                    message="matplotlib not available — spectrogram computed but not saved as image. Install: pip install matplotlib",
                    confidence="LOW",
                ))

        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"Spectrogram generation failed: {e}",
                confidence="LOW",
            ))
        finally:
            if converted and wav_path and wav_path.exists():
                try:
                    wav_path.unlink()
                except Exception:
                    pass

        return findings, None

    @staticmethod
    def _convert_to_wav(path: Path) -> tuple[Path | None, bool, str | None]:
        """Try to convert an audio file to WAV using ffmpeg."""
        try:
            tmp_dir = tempfile.mkdtemp(prefix="watson_audio_")
            wav_out = Path(tmp_dir) / f"{path.stem}.wav"
            result = subprocess.run(
                ["ffmpeg", "-i", str(path), "-ar", "44100", "-ac", "1", str(wav_out), "-y"],
                capture_output=True, timeout=30,
            )
            if result.returncode == 0 and wav_out.exists():
                return wav_out, True, None
            return None, False, "ffmpeg conversion failed"
        except FileNotFoundError:
            return None, False, "ffmpeg not found"
        except subprocess.TimeoutExpired:
            return None, False, "ffmpeg timed out"
        except Exception as e:
            return None, False, str(e)

    # ------------------------------------------------------------------
    # WAV LSB analysis
    # ------------------------------------------------------------------

    def _wav_lsb(self, path: Path) -> List[Finding]:
        """Check LSB of WAV sample data for hidden content."""
        findings: List[Finding] = []
        try:
            import scipy.io.wavfile as wavfile  # type: ignore
            import numpy as np  # type: ignore
        except ImportError:
            return findings

        try:
            sample_rate, data = wavfile.read(str(path))
        except Exception:
            return findings

        if data.dtype not in (
            "int16", "int32", "uint8",
        ):
            return findings

        if data.ndim > 1:
            data = data[:, 0]

        # Extract LSBs
        lsb_bits = (data & 1).astype("uint8")
        # Pack into bytes
        chars = []
        for i in range(0, len(lsb_bits) - 7, 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | int(lsb_bits[i + j])
            if 0x20 <= byte_val <= 0x7E:
                chars.append(chr(byte_val))
            elif byte_val == 0:
                break
            else:
                if len(chars) >= 8:
                    break
                chars = []

        text = "".join(chars)
        if len(text) >= 8:
            flag = self._flag_pattern(text)
            if flag:
                findings.append(Finding(
                    technique=self.name,
                    message=f"LSB in WAV samples decoded to flag: {flag}",
                    confidence="HIGH",
                    flag=flag,
                ))
            else:
                findings.append(Finding(
                    technique=self.name,
                    message=f"LSB in WAV samples decoded to text: {text[:100]}",
                    confidence="MED",
                ))

        return findings
