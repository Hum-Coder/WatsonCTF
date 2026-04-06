"""
Image metadata technique — uses Pillow to read EXIF and other metadata.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from watson.techniques.base import BaseTechnique, Finding

_IMAGE_MIMES = {
    "image/jpeg", "image/png", "image/gif", "image/tiff",
    "image/bmp", "image/webp", "image/x-ms-bmp",
}


class ImageMetadata(BaseTechnique):
    name = "image_metadata"
    description = "Examine image EXIF and metadata for hidden data, GPS coordinates, or unusual fields."

    def applicable(self, path: Path, mime: str) -> bool:
        return mime in _IMAGE_MIMES or mime.startswith("image/")

    def examine(self, path: Path) -> List[Finding]:
        try:
            findings: List[Finding] = []
            try:
                from PIL import Image, UnidentifiedImageError
                from PIL.ExifTags import TAGS, GPSTAGS
            except ImportError:
                findings.append(Finding(
                    technique=self.name,
                    message="Pillow not available — image metadata analysis skipped.",
                    confidence="LOW",
                ))
                return findings

            try:
                img = Image.open(str(path))
            except (OSError, UnidentifiedImageError) as e:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Could not open image: {e}",
                    confidence="LOW",
                ))
                return findings

            # --- Image dimensions anomaly ---
            width, height = img.size
            if width <= 1 or height <= 1:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Suspiciously small image dimensions: {width}x{height} — possible hidden data container.",
                    confidence="MED",
                ))
            elif (width == height) and width in {1, 2, 4, 8, 16}:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Unusual image dimensions: {width}x{height}",
                    confidence="LOW",
                ))

            # --- EXIF ---
            exif_data = {}
            try:
                raw_exif = img._getexif()  # type: ignore[attr-defined]
                if raw_exif:
                    exif_data = {TAGS.get(k, str(k)): v for k, v in raw_exif.items()}
            except (AttributeError, KeyError, TypeError):
                pass

            # Try getexif() (Pillow >= 6.0)
            if not exif_data:
                try:
                    exif_obj = img.getexif()
                    if exif_obj:
                        exif_data = {TAGS.get(k, str(k)): v for k, v in exif_obj.items()}
                except (AttributeError, KeyError, TypeError):
                    pass

            if not exif_data:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Image format: {img.format}, mode: {img.mode}, size: {width}x{height}. No EXIF data found.",
                    confidence="LOW",
                ))
                return findings

            # --- GPS coordinates ---
            if "GPSInfo" in exif_data:
                try:
                    gps_raw = exif_data["GPSInfo"]
                    gps = {GPSTAGS.get(k, str(k)): v for k, v in gps_raw.items()} if isinstance(gps_raw, dict) else {}
                    lat = self._parse_gps(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
                    lon = self._parse_gps(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
                    if lat is not None and lon is not None:
                        findings.append(Finding(
                            technique=self.name,
                            message=f"GPS coordinates embedded: {lat:.6f}, {lon:.6f} — unusual for a CTF image.",
                            confidence="HIGH",
                        ))
                    else:
                        findings.append(Finding(
                            technique=self.name,
                            message=f"GPS metadata present: {gps}",
                            confidence="MED",
                        ))
                except (AttributeError, KeyError, TypeError) as e:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"GPS metadata present but could not parse: {e}",
                        confidence="MED",
                    ))

            # --- Software field ---
            software = exif_data.get("Software", "")
            if software:
                flag = self._flag_pattern(str(software))
                if flag:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Flag found in EXIF Software field: {software}",
                        confidence="HIGH",
                        flag=flag,
                    ))
                else:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"EXIF Software: {str(software)[:120]}",
                        confidence="LOW",
                    ))

            # --- UserComment ---
            user_comment = exif_data.get("UserComment", b"")
            if user_comment:
                # UserComment is bytes with a charset prefix
                try:
                    if isinstance(user_comment, bytes):
                        # Strip ASCII/UNICODE/JIS charset prefix (8 bytes)
                        text = user_comment[8:].decode("utf-8", errors="replace").strip("\x00").strip()
                    else:
                        text = str(user_comment).strip()
                except (AttributeError, KeyError, TypeError):
                    text = repr(user_comment)

                if text:
                    flag = self._flag_pattern(text)
                    if flag:
                        findings.append(Finding(
                            technique=self.name,
                            message=f"Flag found in EXIF UserComment: {text[:120]}",
                            confidence="HIGH",
                            flag=flag,
                        ))
                    else:
                        findings.append(Finding(
                            technique=self.name,
                            message=f"EXIF UserComment: {text[:120]}",
                            confidence="MED",
                        ))

            # --- Scan all EXIF fields for flag patterns ---
            unusual_fields = []
            skip_fields = {"GPSInfo", "Software", "UserComment", "MakerNote", "PrintImageMatching"}
            for tag, value in exif_data.items():
                if tag in skip_fields:
                    continue
                val_str = str(value)
                flag = self._flag_pattern(val_str)
                if flag:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Flag found in EXIF field '{tag}': {val_str[:120]}",
                        confidence="HIGH",
                        flag=flag,
                    ))
                # Note interesting / unusual non-standard tags
                elif tag not in self._COMMON_EXIF_TAGS:
                    unusual_fields.append(f"{tag}={val_str[:40]}")

            if unusual_fields:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Unusual EXIF fields: {', '.join(unusual_fields[:5])}",
                    confidence="LOW",
                ))

            # If we found EXIF but nothing interesting at all
            if len(findings) == 0:
                findings.append(Finding(
                    technique=self.name,
                    message=f"EXIF present ({len(exif_data)} fields). Nothing unusual detected.",
                    confidence="LOW",
                ))

            return findings
        except Exception as e:
            return [Finding(
                technique=self.name,
                message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                confidence="LOW",
            )]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_gps(coords, ref) -> float | None:
        """Convert GPS DMS tuple to decimal degrees."""
        if coords is None:
            return None
        try:
            d, m, s = coords
            # Handle IFDRational or float
            def to_float(v):
                try:
                    return float(v)
                except Exception:
                    return float(v.numerator) / float(v.denominator)
            decimal = to_float(d) + to_float(m) / 60 + to_float(s) / 3600
            if ref in ("S", "W"):
                decimal = -decimal
            return decimal
        except Exception:
            return None

    _COMMON_EXIF_TAGS = {
        "ImageWidth", "ImageLength", "BitsPerSample", "Compression",
        "PhotometricInterpretation", "Make", "Model", "Orientation",
        "SamplesPerPixel", "XResolution", "YResolution", "ResolutionUnit",
        "DateTime", "ExifOffset", "ExposureTime", "FNumber", "ExposureProgram",
        "ISOSpeedRatings", "DateTimeOriginal", "DateTimeDigitized",
        "ShutterSpeedValue", "ApertureValue", "Flash", "FocalLength",
        "ColorSpace", "ExifImageWidth", "ExifImageHeight", "WhiteBalance",
        "LensModel", "Artist", "Copyright",
    }
