#!/usr/bin/env python3
"""
iOS 6 Backup Extractor — Core extraction engine.

Parses Manifest.mbdb from an unencrypted iOS 5/6 iTunes backup and extracts
media files, messages, contacts, notes, calendar events, Safari data, app
data, and more into organized, human-readable output folders.

Can be used standalone (CLI) or driven by the GUI (gui.py).

Usage (CLI):
    python extract_backup.py <backup_folder> [output_folder]
    python extract_backup.py --help
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import json
import logging
import os
import plistlib
import re
import shutil
import sqlite3
import struct
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("ios6extract")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
APPLE_EPOCH_OFFSET = 978307200  # seconds between 1970‑01‑01 and 2001‑01‑01

MEDIA_IMAGE_EXTS = frozenset(
    (".jpg", ".jpeg", ".png", ".gif", ".heic", ".heif", ".tiff", ".bmp")
)
MEDIA_VIDEO_EXTS = frozenset((".mov", ".mp4", ".m4v", ".avi", ".3gp", ".mkv"))
MEDIA_AUDIO_EXTS = frozenset(
    (".mp3", ".m4a", ".aac", ".wav", ".aiff", ".m4p", ".m4b", ".caf", ".amr")
)
INTERESTING_APP_EXTS = frozenset(
    (
        ".sqlite", ".sqlitedb", ".db",
        ".plist", ".json", ".xml", ".csv",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".mp3", ".m4a", ".wav", ".caf",
        ".mp4", ".mov", ".m4v",
        ".pdf", ".doc", ".docx", ".txt", ".rtf",
        ".html", ".htm",
    )
)

# Characters illegal in Windows file/directory names
_WIN_BAD_CHARS = re.compile(r'[<>:"/\\|?*]')


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class MBDBEntry:
    """One record parsed from Manifest.mbdb."""
    domain: str
    path: str
    sha1: str  # hex digest used as backup filename
    mode: int
    is_file: bool
    is_dir: bool
    is_symlink: bool
    size: int
    mtime: int
    properties: Dict[str, str] = field(default_factory=dict)


@dataclass
class ExtractionStats:
    """Thread-safe extraction statistics."""
    _data: Dict[str, int] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)
    _errors: List[str] = field(default_factory=list)

    def add(self, category: str, count: int) -> None:
        with self._lock:
            self._data[category] = self._data.get(category, 0) + count

    def set(self, category: str, count: int) -> None:
        with self._lock:
            self._data[category] = count

    def add_error(self, msg: str) -> None:
        with self._lock:
            self._errors.append(msg)

    @property
    def totals(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._data)

    @property
    def errors(self) -> List[str]:
        with self._lock:
            return list(self._errors)

    @property
    def grand_total(self) -> int:
        with self._lock:
            return sum(self._data.values())


# ---------------------------------------------------------------------------
# Progress callback type
# ---------------------------------------------------------------------------
# signature: (message: str, detail: str, fraction: float | None)
ProgressCallback = Optional[Callable[[str, str, Optional[float]], None]]


# ---------------------------------------------------------------------------
# MBDB binary parser
# ---------------------------------------------------------------------------
def _read_mbdb_string(f) -> Optional[str]:
    raw = f.read(2)
    if len(raw) < 2:
        return None
    length = struct.unpack(">H", raw)[0]
    if length == 0xFFFF:
        return ""
    data = f.read(length)
    return data.decode("utf-8", errors="replace") if len(data) == length else None


def _read_mbdb_raw(f) -> Optional[bytes]:
    raw = f.read(2)
    if len(raw) < 2:
        return None
    length = struct.unpack(">H", raw)[0]
    if length == 0xFFFF:
        return b""
    data = f.read(length)
    return data if len(data) == length else None


def parse_mbdb(mbdb_path: str | Path) -> List[MBDBEntry]:
    """Parse *Manifest.mbdb* and return a list of `MBDBEntry` objects."""
    entries: list[MBDBEntry] = []
    mbdb_path = Path(mbdb_path)

    if not mbdb_path.is_file():
        raise FileNotFoundError(f"Manifest.mbdb not found at {mbdb_path}")

    with open(mbdb_path, "rb") as f:
        magic = f.read(4)
        if magic != b"mbdb":
            raise ValueError(f"Invalid MBDB: expected b'mbdb', got {magic!r}")
        _version = struct.unpack(">H", f.read(2))[0]

        while True:
            domain = _read_mbdb_string(f)
            if domain is None:
                break
            path = _read_mbdb_string(f)
            if path is None:
                break

            link_target = _read_mbdb_raw(f)
            data_hash = _read_mbdb_raw(f)
            encryption_key = _read_mbdb_raw(f)
            if any(v is None for v in (link_target, data_hash, encryption_key)):
                break

            fixed = f.read(40)
            if len(fixed) < 40:
                break

            mode = struct.unpack(">H", fixed[0:2])[0]
            mtime = struct.unpack(">I", fixed[18:22])[0]
            file_length = struct.unpack(">Q", fixed[30:38])[0]
            num_props = struct.unpack(">B", fixed[39:40])[0]

            props: dict[str, str] = {}
            for _ in range(num_props):
                pn = _read_mbdb_string(f)
                pv = _read_mbdb_raw(f)
                if pn is None or pv is None:
                    break
                try:
                    props[pn] = pv.decode("utf-8")
                except (UnicodeDecodeError, AttributeError):
                    props[pn] = pv.hex() if pv else ""

            sha1 = hashlib.sha1(f"{domain}-{path}".encode()).hexdigest()

            entries.append(
                MBDBEntry(
                    domain=domain,
                    path=path,
                    sha1=sha1,
                    mode=mode,
                    is_file=(mode & 0xF000) == 0x8000,
                    is_dir=(mode & 0xF000) == 0x4000,
                    is_symlink=(mode & 0xF000) == 0xA000,
                    size=file_length,
                    mtime=mtime,
                    properties=props,
                )
            )
    return entries


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def apple_ts(ts) -> str:
    """Apple Core Data timestamp → readable string."""
    if not ts:
        return "N/A"
    try:
        return datetime.datetime.fromtimestamp(
            ts + APPLE_EPOCH_OFFSET
        ).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return f"timestamp({ts})"


def unix_ts(ts) -> str:
    if not ts:
        return "N/A"
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return f"timestamp({ts})"


def format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.2f} PB"


def _sanitize_win_path(p: str) -> str:
    """Replace characters illegal on Windows in path *components*."""
    return _WIN_BAD_CHARS.sub("_", p)


def _find_backup_file(backup_dir: Path, sha1: str) -> Optional[Path]:
    """Locate the blob in the flat or two-level backup layout."""
    p = backup_dir / sha1
    if p.is_file():
        return p
    p2 = backup_dir / sha1[:2] / sha1
    if p2.is_file():
        return p2
    return None


def _safe_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _ext(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def _open_sqlite(backup_dir: Path, entry: MBDBEntry, temp_dir: Path):
    """Copy a SQLite db out of the backup to *temp_dir* and open it."""
    src = _find_backup_file(backup_dir, entry.sha1)
    if src is None:
        return None, None
    tmp = temp_dir / f"{entry.sha1}_{os.path.basename(entry.path)}"
    _safe_copy(src, tmp)
    try:
        conn = sqlite3.connect(str(tmp))
        conn.row_factory = sqlite3.Row
        return conn, tmp
    except sqlite3.Error as exc:
        log.warning("Cannot open %s: %s", entry.path, exc)
        return None, None


def _tables(conn: sqlite3.Connection) -> List[str]:
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return [r[0] for r in cur.fetchall()]


def _columns(conn: sqlite3.Connection, table: str) -> List[str]:
    cur = conn.execute(f"PRAGMA table_info({table})")
    return [r[1] for r in cur.fetchall()]


def _strip_html(html: str) -> str:
    """Minimal HTML→text conversion for Notes content."""
    text = re.sub(r"<br\s*/?>", "\n", html, flags=re.I)
    text = re.sub(r"<div[^>]*>", "\n", text, flags=re.I)
    text = re.sub(r"</div>", "", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


# ---------------------------------------------------------------------------
# Individual extractor functions
# ---------------------------------------------------------------------------
# Each returns an int count, accepts (entries, backup_dir, out, …).
# They are designed to be safe to run in any order and in parallel (the
# media ones are embarrassingly parallel; the SQLite ones share temp_dir
# but use unique file names keyed on SHA1).

def _extract_camera_roll(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, on_file=None, **_kw
) -> int:
    dst_root = out / "Photos_and_Videos" / "Camera_Roll"
    count = 0
    for e in entries:
        if e.domain == "CameraRollDomain" and e.is_file:
            ext = _ext(e.path)
            if ext in MEDIA_IMAGE_EXTS | MEDIA_VIDEO_EXTS:
                src = _find_backup_file(backup_dir, e.sha1)
                if src:
                    rel = _sanitize_win_path(e.path.replace("/", os.sep))
                    _safe_copy(src, dst_root / rel)
                    count += 1
                    if on_file:
                        on_file("Camera Roll", count)
    return count


def _extract_photo_data(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, **_kw
) -> int:
    dst_root = out / "Photos_and_Videos" / "PhotoData"
    count = 0
    for e in entries:
        if e.domain == "MediaDomain" and e.is_file:
            if "PhotoData" in e.path or "Photos" in e.path:
                ext = _ext(e.path)
                if ext in MEDIA_IMAGE_EXTS | MEDIA_VIDEO_EXTS:
                    src = _find_backup_file(backup_dir, e.sha1)
                    if src:
                        rel = _sanitize_win_path(e.path.replace("/", os.sep))
                        _safe_copy(src, dst_root / rel)
                        count += 1
    return count


def _extract_videos(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, **_kw
) -> int:
    dst_root = out / "Videos"
    count, seen = 0, set()
    for e in entries:
        if e.is_file and e.sha1 not in seen and e.domain != "CameraRollDomain":
            if _ext(e.path) in MEDIA_VIDEO_EXTS:
                src = _find_backup_file(backup_dir, e.sha1)
                if src:
                    rel = _sanitize_win_path(e.path.replace("/", os.sep))
                    _safe_copy(src, dst_root / e.domain / rel)
                    seen.add(e.sha1)
                    count += 1
    return count


def _extract_music(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, **_kw
) -> int:
    dst_root = out / "Music"
    count = 0
    for e in entries:
        if e.is_file and _ext(e.path) in MEDIA_AUDIO_EXTS and e.size > 50_000:
            src = _find_backup_file(backup_dir, e.sha1)
            if src:
                rel = _sanitize_win_path(e.path.replace("/", os.sep))
                _safe_copy(src, dst_root / e.domain / rel)
                count += 1
    return count


def _extract_voice_memos(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, **_kw
) -> int:
    dst_root = out / "Voice_Memos"
    count = 0
    for e in entries:
        if e.is_file:
            pl = e.path.lower()
            if ("recording" in pl or "voicememo" in pl or "voice memo" in pl):
                if _ext(e.path) in MEDIA_AUDIO_EXTS:
                    src = _find_backup_file(backup_dir, e.sha1)
                    if src:
                        _safe_copy(src, dst_root / os.path.basename(e.path))
                        count += 1
    return count


def _extract_wallpapers(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, **_kw
) -> int:
    dst_root = out / "Wallpapers"
    count = 0
    for e in entries:
        if e.is_file:
            pl = e.path.lower()
            if any(k in pl for k in ("wallpaper", "lockbackground", "homebackground", "lockscreen")):
                if _ext(e.path) in (".jpg", ".jpeg", ".png", ".cpbitmap", ".gif"):
                    src = _find_backup_file(backup_dir, e.sha1)
                    if src:
                        _safe_copy(src, dst_root / f"{e.domain}_{os.path.basename(e.path)}")
                        count += 1
    return count


# ---- SQLite extractors ----------------------------------------------------

def _extract_sms(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, temp_dir: Path, **_kw
) -> int:
    sms_entry = next(
        (e for e in entries if e.is_file and e.path.endswith("sms.db") and "SMS" in e.path),
        None,
    )
    if sms_entry is None:
        log.info("sms.db not found")
        return 0

    conn, _ = _open_sqlite(backup_dir, sms_entry, temp_dir)
    if conn is None:
        return 0

    try:
        tables = _tables(conn)
        messages: list[dict] = []

        # new iOS 6 schema
        if "handle" in tables and "chat_message_join" in tables:
            try:
                rows = conn.execute(
                    "SELECT m.ROWID, m.text, m.date, m.is_from_me, m.service, "
                    "h.id FROM message m LEFT JOIN handle h ON m.handle_id=h.ROWID "
                    "ORDER BY m.date"
                ).fetchall()
                for r in rows:
                    messages.append(dict(
                        id=r[0], text=r[1] or "", date=apple_ts(r[2]),
                        is_from_me=bool(r[3]), service=r[4] or "SMS",
                        address=r[5] or "Unknown",
                    ))
            except sqlite3.OperationalError:
                pass

        # old flat schema fallback
        if not messages and "message" in tables:
            cols = _columns(conn, "message")
            try:
                if "address" in cols:
                    for r in conn.execute(
                        "SELECT ROWID,address,date,text,flags FROM message ORDER BY date"
                    ).fetchall():
                        messages.append(dict(
                            id=r[0], address=r[1] or "Unknown",
                            date=unix_ts(r[2]), text=r[3] or "",
                            is_from_me=bool((r[4] or 0) & 1), service="SMS",
                        ))
                elif "handle_id" in cols:
                    for r in conn.execute(
                        "SELECT ROWID,handle_id,date,text,is_from_me,service "
                        "FROM message ORDER BY date"
                    ).fetchall():
                        addr = str(r[1])
                        if "handle" in tables:
                            hr = conn.execute(
                                "SELECT id FROM handle WHERE ROWID=?", (r[1],)
                            ).fetchone()
                            if hr:
                                addr = hr[0]
                        messages.append(dict(
                            id=r[0], address=addr, date=apple_ts(r[2]),
                            text=r[3] or "", is_from_me=bool(r[4]),
                            service=r[5] or "SMS",
                        ))
            except sqlite3.OperationalError:
                pass

        # group by contact
        convos: dict[str, list[dict]] = {}
        for m in messages:
            convos.setdefault(m["address"], []).append(m)

        sms_dir = out / "Messages"
        sms_dir.mkdir(parents=True, exist_ok=True)

        # all_messages.txt
        with open(sms_dir / "all_messages.txt", "w", encoding="utf-8") as f:
            f.write(f"SMS / iMessage Export — {len(messages)} messages, "
                    f"{len(convos)} conversations\n{'=' * 80}\n\n")
            for addr in sorted(convos):
                msgs = convos[addr]
                f.write(f"\n{'=' * 60}\nConversation with: {addr} ({len(msgs)} msgs)\n{'=' * 60}\n\n")
                for m in msgs:
                    who = "Me" if m["is_from_me"] else addr
                    f.write(f"[{m['date']}] {who}:\n  {m['text']}\n\n")

        # CSV
        with open(sms_dir / "all_messages.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ID", "Address", "Date", "FromMe", "Service", "Text"])
            for m in messages:
                w.writerow([m["id"], m["address"], m["date"], m["is_from_me"], m["service"], m["text"]])

        # per-conversation
        conv_dir = sms_dir / "conversations"
        conv_dir.mkdir(exist_ok=True)
        for addr, msgs in convos.items():
            safe = re.sub(r"[^\w\-+]", "_", addr)
            with open(conv_dir / f"{safe}.txt", "w", encoding="utf-8") as f:
                f.write(f"Conversation with: {addr}\n{'=' * 40}\n\n")
                for m in msgs:
                    who = "Me" if m["is_from_me"] else addr
                    f.write(f"[{m['date']}] {who}: {m['text']}\n")

        # attachments
        att_count = 0
        if "attachment" in tables:
            try:
                att_dir = sms_dir / "attachments"
                for r in conn.execute("SELECT ROWID,filename,mime_type,transfer_name FROM attachment"):
                    att_fn = r[1] or r[3] or f"attachment_{r[0]}"
                    bn = os.path.basename(att_fn)
                    for e in entries:
                        if e.is_file and bn and e.path.endswith(bn) and ("Attachment" in e.path or "SMS" in e.path):
                            src = _find_backup_file(backup_dir, e.sha1)
                            if src:
                                _safe_copy(src, att_dir / bn)
                                att_count += 1
                            break
            except sqlite3.OperationalError:
                pass

        conn.close()
        return len(messages) + att_count
    except Exception as exc:
        log.error("SMS extraction failed: %s", exc, exc_info=True)
        conn.close()
        return 0


def _extract_notes(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, temp_dir: Path, **_kw
) -> int:
    entry = next((e for e in entries if e.is_file and e.path.endswith("notes.sqlite")), None)
    if entry is None:
        log.info("notes.sqlite not found")
        return 0

    conn, _ = _open_sqlite(backup_dir, entry, temp_dir)
    if conn is None:
        return 0

    try:
        tables = _tables(conn)
        notes: list[dict] = []

        if "ZNOTE" in tables:
            # Try with ZNOTEBODY join
            if "ZNOTEBODY" in tables:
                try:
                    for r in conn.execute(
                        "SELECT n.Z_PK,n.ZCREATIONDATE,n.ZMODIFICATIONDATE,"
                        "n.ZTITLE,b.ZCONTENT FROM ZNOTE n "
                        "LEFT JOIN ZNOTEBODY b ON b.ZOWNER=n.Z_PK ORDER BY n.ZCREATIONDATE"
                    ):
                        notes.append(dict(id=r[0], created=apple_ts(r[1]),
                                          modified=apple_ts(r[2]),
                                          title=r[3] or "(Untitled)", content=r[4] or ""))
                except sqlite3.OperationalError:
                    pass

            # Fallback: body column lives directly on ZNOTE
            if not notes or all(not n["content"] for n in notes):
                cols = _columns(conn, "ZNOTE")
                body_col = next((c for c in ("ZBODY", "ZCONTENT", "ZTEXT", "ZSUMMARY") if c in cols), None)
                if body_col:
                    try:
                        notes2 = []
                        for r in conn.execute(
                            f"SELECT Z_PK,ZCREATIONDATE,ZMODIFICATIONDATE,ZTITLE,{body_col} "
                            "FROM ZNOTE ORDER BY ZCREATIONDATE"
                        ):
                            notes2.append(dict(id=r[0], created=apple_ts(r[1]),
                                               modified=apple_ts(r[2]),
                                               title=r[3] or "(Untitled)", content=r[4] or ""))
                        if any(n["content"] for n in notes2):
                            notes = notes2
                    except sqlite3.OperationalError:
                        pass

        ndir = out / "Notes"
        ndir.mkdir(parents=True, exist_ok=True)

        with open(ndir / "all_notes.txt", "w", encoding="utf-8") as f:
            f.write(f"Notes Export — {len(notes)} notes\n{'=' * 80}\n\n")
            for n in notes:
                f.write(f"\n{'─' * 60}\nTitle: {n['title']}\nCreated: {n['created']}\n"
                        f"Modified: {n['modified']}\n{'─' * 60}\n{_strip_html(n['content'])}\n\n")

        ind = ndir / "individual"
        ind.mkdir(exist_ok=True)
        for n in notes:
            safe = re.sub(r"[^\w \-]", "_", n["title"])[:50]
            with open(ind / f"{n['id']:03d}_{safe}.txt", "w", encoding="utf-8") as f:
                f.write(f"Title: {n['title']}\nCreated: {n['created']}\nModified: {n['modified']}\n\n")
                f.write(_strip_html(n["content"]) + "\n")

        conn.close()
        return len(notes)
    except Exception as exc:
        log.error("Notes extraction: %s", exc, exc_info=True)
        conn.close()
        return 0


def _extract_contacts(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, temp_dir: Path, **_kw
) -> int:
    entry = next((e for e in entries if e.is_file and e.path.endswith("AddressBook.sqlitedb")), None)
    if entry is None:
        log.info("AddressBook not found")
        return 0

    conn, _ = _open_sqlite(backup_dir, entry, temp_dir)
    if conn is None:
        return 0

    try:
        tables = _tables(conn)
        contacts: list[dict] = []

        for r in conn.execute("SELECT ROWID, * FROM ABPerson"):
            person = dict(r)
            rowid = person.get("ROWID")
            c = dict(id=rowid, first=person.get("First") or "",
                     last=person.get("Last") or "",
                     org=person.get("Organization") or "",
                     dept=person.get("Department") or "",
                     note=person.get("Note") or "",
                     birthday=person.get("Birthday") or "",
                     phones=[], emails=[], addresses=[], urls=[])

            if "ABMultiValue" in tables:
                try:
                    for mv in conn.execute(
                        "SELECT property,label,value FROM ABMultiValue WHERE record_id=? ORDER BY property",
                        (rowid,),
                    ):
                        prop, label, value = mv
                        if not value:
                            continue
                        label = str(label).replace("_$!<", "").replace(">!$_", "").strip() if label is not None else ""
                        entry_str = f"{label}: {value}" if label else str(value)
                        if prop == 3:
                            c["phones"].append(entry_str)
                        elif prop == 4:
                            c["emails"].append(entry_str)
                        elif prop == 5:
                            c["addresses"].append(str(value))
                        elif prop == 22:
                            c["urls"].append(str(value))
                except sqlite3.OperationalError as exc:
                    log.warning("ABMultiValue: %s", exc)

            contacts.append(c)

        cdir = out / "Contacts"
        cdir.mkdir(parents=True, exist_ok=True)

        # txt
        with open(cdir / "all_contacts.txt", "w", encoding="utf-8") as f:
            f.write(f"Contacts — {len(contacts)}\n{'=' * 80}\n\n")
            for c in contacts:
                name = f"{c['first']} {c['last']}".strip() or c["org"] or "(No Name)"
                f.write(f"\n{'─' * 40}\nName: {name}\n")
                if c["org"]:
                    f.write(f"Org: {c['org']}\n")
                for p in c["phones"]:
                    f.write(f"Phone: {p}\n")
                for e in c["emails"]:
                    f.write(f"Email: {e}\n")
                if c["note"]:
                    f.write(f"Note: {c['note']}\n")

        # csv
        with open(cdir / "all_contacts.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["First", "Last", "Organization", "Phones", "Emails", "Note"])
            for c in contacts:
                w.writerow([c["first"], c["last"], c["org"],
                            " | ".join(c["phones"]), " | ".join(c["emails"]), c["note"]])

        # vcf
        with open(cdir / "all_contacts.vcf", "w", encoding="utf-8") as f:
            for c in contacts:
                f.write("BEGIN:VCARD\nVERSION:3.0\n")
                f.write(f"N:{c['last']};{c['first']};;;\nFN:{c['first']} {c['last']}\n")
                if c["org"]:
                    f.write(f"ORG:{c['org']}\n")
                for p in c["phones"]:
                    f.write(f"TEL:{p.split(': ',1)[-1] if ': ' in p else p}\n")
                for e in c["emails"]:
                    f.write(f"EMAIL:{e.split(': ',1)[-1] if ': ' in e else e}\n")
                if c["note"]:
                    f.write(f"NOTE:{c['note']}\n")
                f.write("END:VCARD\n\n")

        conn.close()
        return len(contacts)
    except Exception as exc:
        log.error("Contacts: %s", exc, exc_info=True)
        conn.close()
        return 0


def _extract_call_history(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, temp_dir: Path, **_kw
) -> int:
    entry = next(
        (e for e in entries if e.is_file and "call_history" in e.path.lower() and e.path.endswith(".db")),
        None,
    )
    if entry is None:
        return 0

    conn, _ = _open_sqlite(backup_dir, entry, temp_dir)
    if conn is None:
        return 0

    try:
        tables = _tables(conn)
        calls: list[dict] = []
        if "call" in tables:
            for r in conn.execute("SELECT * FROM call ORDER BY date"):
                calls.append(dict(r))

        if calls:
            d = out / "Call_History"
            d.mkdir(parents=True, exist_ok=True)
            with open(d / "call_history.txt", "w", encoding="utf-8") as f:
                f.write(f"Call History — {len(calls)} calls\n{'=' * 80}\n\n")
                for c in calls:
                    f.write(f"[{unix_ts(c.get('date',0))}] {c.get('address','?')} "
                            f"({c.get('duration',0)}s)\n")
            with open(d / "call_history.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=calls[0].keys())
                w.writeheader()
                w.writerows(calls)

        conn.close()
        return len(calls)
    except Exception as exc:
        log.error("Call history: %s", exc, exc_info=True)
        conn.close()
        return 0


def _extract_safari(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, temp_dir: Path, **_kw
) -> int:
    total = 0
    sdir = out / "Safari"
    sdir.mkdir(parents=True, exist_ok=True)

    # bookmarks
    bm_e = next((e for e in entries if e.is_file and e.path.endswith("Bookmarks.db") and "Safari" in e.path), None)
    if bm_e:
        conn, _ = _open_sqlite(backup_dir, bm_e, temp_dir)
        if conn:
            try:
                bms = conn.execute(
                    "SELECT title, url FROM bookmarks WHERE url IS NOT NULL AND url != ''"
                ).fetchall()
                if bms:
                    with open(sdir / "bookmarks.txt", "w", encoding="utf-8") as f:
                        f.write(f"Safari Bookmarks — {len(bms)}\n{'=' * 80}\n\n")
                        for b in bms:
                            f.write(f"  {b[0] or '(no title)'}\n    {b[1]}\n\n")
                    total += len(bms)
            except Exception as exc:
                log.warning("Bookmarks: %s", exc)
            conn.close()

    # history plist (common on iOS 5/6)
    hp = next((e for e in entries if e.is_file and e.path.endswith("History.plist") and "Safari" in e.path), None)
    if hp:
        src = _find_backup_file(backup_dir, hp.sha1)
        if src:
            try:
                with open(src, "rb") as f:
                    pd = plistlib.load(f)
                items = pd if isinstance(pd, list) else pd.get("WebHistoryDates", [])
                with open(sdir / "history.txt", "w", encoding="utf-8") as f:
                    f.write(f"Safari History — {len(items)} items\n{'=' * 80}\n\n")
                    for it in items:
                        if isinstance(it, dict):
                            f.write(f"  {it.get('title', it.get('displayTitle', ''))}\n"
                                    f"    {it.get('', it.get('url', ''))}\n\n")
                total += len(items)
            except Exception as exc:
                log.warning("History plist: %s", exc)

    return total


def _extract_calendar(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, temp_dir: Path, **_kw
) -> int:
    entry = next((e for e in entries if e.is_file and e.path.endswith("Calendar.sqlitedb")), None)
    if entry is None:
        return 0

    conn, _ = _open_sqlite(backup_dir, entry, temp_dir)
    if conn is None:
        return 0

    try:
        events: list[dict] = []
        if "CalendarItem" in _tables(conn):
            for r in conn.execute("SELECT * FROM CalendarItem"):
                events.append(dict(r))

        if events:
            d = out / "Calendar"
            d.mkdir(parents=True, exist_ok=True)
            with open(d / "calendar_events.txt", "w", encoding="utf-8") as f:
                f.write(f"Calendar — {len(events)} events\n{'=' * 80}\n\n")
                for ev in events:
                    f.write(f"  {ev.get('summary', '(No title)')}\n"
                            f"    Start: {apple_ts(ev.get('start_date',0))}\n"
                            f"    End:   {apple_ts(ev.get('end_date',0))}\n\n")
            with open(d / "calendar_events.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=events[0].keys())
                w.writeheader()
                w.writerows(events)

        conn.close()
        return len(events)
    except Exception as exc:
        log.error("Calendar: %s", exc, exc_info=True)
        conn.close()
        return 0


def _extract_voicemail(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, temp_dir: Path, **_kw
) -> int:
    vdir = out / "Voicemail"
    count = 0
    for e in entries:
        if e.is_file and "voicemail" in e.path.lower() and _ext(e.path) in MEDIA_AUDIO_EXTS:
            src = _find_backup_file(backup_dir, e.sha1)
            if src:
                _safe_copy(src, vdir / os.path.basename(e.path))
                count += 1

    db_e = next((e for e in entries if e.is_file and e.path.endswith("voicemail.db")), None)
    if db_e:
        conn, _ = _open_sqlite(backup_dir, db_e, temp_dir)
        if conn:
            try:
                if "voicemail" in _tables(conn):
                    rows = conn.execute("SELECT * FROM voicemail").fetchall()
                    if rows:
                        vdir.mkdir(parents=True, exist_ok=True)
                        col_names = [d[0] for d in conn.execute("SELECT * FROM voicemail LIMIT 1").description]
                        with open(vdir / "voicemail_list.txt", "w", encoding="utf-8") as f:
                            f.write(f"Voicemail — {len(rows)}\n{'=' * 80}\n\n")
                            for r in rows:
                                vm = dict(zip(col_names, r))
                                f.write(f"  From: {vm.get('sender', vm.get('remote_uid', '?'))}\n"
                                        f"  Date: {unix_ts(vm.get('date', 0))}\n"
                                        f"  Duration: {vm.get('duration', 0)}s\n\n")
            except Exception as exc:
                log.warning("Voicemail DB: %s", exc)
            conn.close()
    return count


def _extract_app_data(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, on_file=None, **_kw
) -> int:
    app_dir = out / "Apps"
    count = 0
    apps: set[str] = set()

    for e in entries:
        if e.is_file and e.domain.startswith("AppDomain-"):
            app_name = e.domain.removeprefix("AppDomain-")
            apps.add(app_name)
            ext = _ext(e.path)
            if ext in INTERESTING_APP_EXTS or e.size > 100_000:
                src = _find_backup_file(backup_dir, e.sha1)
                if src:
                    rel = _sanitize_win_path(e.path.replace("/", os.sep))
                    _safe_copy(src, app_dir / app_name / rel)
                    count += 1
                    if on_file:
                        on_file("App Data", count)

    if apps:
        app_dir.mkdir(parents=True, exist_ok=True)
        with open(app_dir / "_installed_apps.txt", "w", encoding="utf-8") as f:
            f.write(f"Installed Apps ({len(apps)})\n{'=' * 60}\n\n")
            for a in sorted(apps):
                f.write(f"  {a}\n")
    return count


def _extract_wifi(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, **_kw
) -> int:
    for e in entries:
        if e.is_file and ("wifi" in e.path.lower() or "com.apple.wifi" in e.path.lower()):
            src = _find_backup_file(backup_dir, e.sha1)
            if src:
                try:
                    with open(src, "rb") as f:
                        pd = plistlib.load(f)
                    wdir = out / "WiFi"
                    wdir.mkdir(parents=True, exist_ok=True)
                    nets = pd.get("List of known networks", pd.get("KnownNetworks", []))
                    with open(wdir / "wifi_networks.txt", "w", encoding="utf-8") as f:
                        f.write("Saved WiFi Networks\n" + "=" * 60 + "\n\n")
                        if isinstance(nets, list):
                            for n in nets:
                                if isinstance(n, dict):
                                    f.write(f"  SSID: {n.get('SSID_STR', n.get('SSIDString', '?'))}\n\n")
                        elif isinstance(nets, dict):
                            for k, n in nets.items():
                                if isinstance(n, dict):
                                    f.write(f"  SSID: {n.get('SSID_STR', n.get('SSIDString', k))}\n\n")
                    return 1
                except Exception:
                    pass
    return 0


def _extract_plists(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, **_kw
) -> int:
    pdir = out / "Settings_Plists"
    count = 0
    keywords = {"preferences", "accounts", "wifi", "bluetooth", "contacts", "mail", "safari", "keyboard"}
    allowed_domains = {"HomeDomain", "SystemPreferencesDomain", "WirelessDomain"}

    def json_default(obj):
        if isinstance(obj, bytes):
            return f"<bytes:{len(obj)}>"
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return str(obj)

    for e in entries:
        if e.is_file and e.path.endswith(".plist"):
            pl = e.path.lower()
            if not (any(kw in pl for kw in keywords) or e.domain in allowed_domains):
                continue
            src = _find_backup_file(backup_dir, e.sha1)
            if not src:
                continue
            safe_name = _sanitize_win_path(f"{e.domain}__{e.path.replace('/', '_')}")
            try:
                with open(src, "rb") as f:
                    pd = plistlib.load(f)
                dst = pdir / f"{safe_name}.json"
                dst.parent.mkdir(parents=True, exist_ok=True)
                with open(dst, "w", encoding="utf-8") as f:
                    json.dump(pd, f, indent=2, default=json_default, ensure_ascii=False)
                count += 1
            except Exception:
                dst = pdir / safe_name
                dst.parent.mkdir(parents=True, exist_ok=True)
                _safe_copy(src, dst)
                count += 1
    return count


def _extract_raw_databases(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, **_kw
) -> int:
    db_dir = out / "_raw_databases"
    count = 0
    for e in entries:
        if e.is_file and _ext(e.path) in (".db", ".sqlite", ".sqlitedb"):
            src = _find_backup_file(backup_dir, e.sha1)
            if src:
                safe = _sanitize_win_path(f"{e.domain}__{e.path.replace('/', '_')}")
                _safe_copy(src, db_dir / safe)
                count += 1
    return count


def _generate_manifest(
    entries: List[MBDBEntry], backup_dir: Path, out: Path, **_kw
) -> int:
    rdir = out / "_manifest"
    rdir.mkdir(parents=True, exist_ok=True)

    # CSV
    with open(rdir / "full_file_manifest.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Domain", "Path", "SHA1", "Size", "IsFile", "MTime", "ExistsInBackup"])
        for e in entries:
            exists = _find_backup_file(backup_dir, e.sha1) is not None
            w.writerow([e.domain, e.path, e.sha1, e.size, e.is_file, unix_ts(e.mtime), exists])

    # domain summary
    domains: dict[str, dict] = {}
    for e in entries:
        d = domains.setdefault(e.domain, {"files": 0, "dirs": 0, "size": 0})
        if e.is_file:
            d["files"] += 1
            d["size"] += e.size
        elif e.is_dir:
            d["dirs"] += 1

    with open(rdir / "domain_summary.txt", "w", encoding="utf-8") as f:
        f.write("Backup Domain Summary\n" + "=" * 80 + "\n\n")
        f.write(f"{'Domain':<55} {'Files':>6} {'Dirs':>6} {'Size':>12}\n" + "-" * 80 + "\n")
        tf = ts = 0
        for dn in sorted(domains):
            info = domains[dn]
            f.write(f"{dn:<55} {info['files']:>6} {info['dirs']:>6} {format_size(info['size']):>12}\n")
            tf += info["files"]
            ts += info["size"]
        f.write("-" * 80 + f"\n{'TOTAL':<55} {tf:>6} {'':>6} {format_size(ts):>12}\n")

    # missing
    missing = [e for e in entries if e.is_file and _find_backup_file(backup_dir, e.sha1) is None]
    if missing:
        with open(rdir / "missing_files.txt", "w", encoding="utf-8") as f:
            f.write(f"Missing files ({len(missing)})\n{'=' * 80}\n\n")
            for e in missing:
                f.write(f"  [{e.domain}] {e.path} ({format_size(e.size)})\n    hash: {e.sha1}\n\n")

    return len(entries)


# ---------------------------------------------------------------------------
# Extraction orchestrator
# ---------------------------------------------------------------------------
# Two groups: media (parallel-safe, I/O bound) and db (need temp_dir).
_MEDIA_TASKS: List[Tuple[str, Callable]] = [
    ("Camera Roll", _extract_camera_roll),
    ("PhotoData", _extract_photo_data),
    ("Videos", _extract_videos),
    ("Music", _extract_music),
    ("Voice Memos", _extract_voice_memos),
    ("Wallpapers", _extract_wallpapers),
    ("App Data", _extract_app_data),
    ("WiFi", _extract_wifi),
    ("Plists", _extract_plists),
    ("Raw Databases", _extract_raw_databases),
]

_DB_TASKS: List[Tuple[str, Callable]] = [
    ("SMS / iMessage", _extract_sms),
    ("Notes", _extract_notes),
    ("Contacts", _extract_contacts),
    ("Call History", _extract_call_history),
    ("Safari", _extract_safari),
    ("Calendar", _extract_calendar),
    ("Voicemail", _extract_voicemail),
]


def validate_backup(backup_dir: str | Path) -> Tuple[bool, str]:
    """
    Pre-flight check on a backup directory.
    Returns (ok, message).
    """
    bd = Path(backup_dir)
    if not bd.is_dir():
        return False, f"Directory does not exist: {bd}"
    mbdb = bd / "Manifest.mbdb"
    if not mbdb.is_file():
        return False, f"Manifest.mbdb not found in {bd}"
    try:
        with open(mbdb, "rb") as f:
            magic = f.read(4)
        if magic != b"mbdb":
            return False, f"Manifest.mbdb has invalid header: {magic!r}"
    except OSError as exc:
        return False, f"Cannot read Manifest.mbdb: {exc}"

    # Check encryption
    mp = bd / "Manifest.plist"
    if mp.is_file():
        try:
            with open(mp, "rb") as f:
                mdata = plistlib.load(f)
            if mdata.get("IsEncrypted"):
                return False, "Backup is encrypted. This tool only supports unencrypted backups."
        except Exception:
            pass  # non-fatal

    return True, "Backup looks valid."


def get_device_info(backup_dir: str | Path) -> Dict[str, str]:
    """Read device Info.plist; returns a dict of key fields."""
    ip = Path(backup_dir) / "Info.plist"
    if not ip.is_file():
        return {}
    try:
        with open(ip, "rb") as f:
            data = plistlib.load(f)
        return {
            "device": data.get("Product Name", "Unknown"),
            "model": data.get("Product Type", ""),
            "name": data.get("Display Name", "Unknown"),
            "ios_version": data.get("Product Version", "?"),
            "build": data.get("Build Version", ""),
            "serial": data.get("Serial Number", ""),
        }
    except Exception:
        return {}


def run_extraction(
    backup_dir: str | Path,
    output_dir: str | Path,
    *,
    max_workers: int = 4,
    include_raw: bool = True,
    progress: ProgressCallback = None,
) -> ExtractionStats:
    """
    Run the full extraction pipeline.

    Parameters
    ----------
    backup_dir : path to the iOS backup folder with Manifest.mbdb
    output_dir : where to write extracted files
    max_workers : thread pool size for media-file copy tasks
    include_raw : if False, skip raw databases, plists, and manifest report
    progress : optional callback ``(phase, detail, fraction)``

    Returns
    -------
    ExtractionStats with per-category counts and error list.
    """
    bd = Path(backup_dir).resolve()
    od = Path(output_dir).resolve()
    od.mkdir(parents=True, exist_ok=True)
    tmp = od / "_temp"
    tmp.mkdir(exist_ok=True)

    stats = ExtractionStats()

    def _progress(phase: str, detail: str = "", frac: float | None = None):
        if progress:
            try:
                progress(phase, detail, frac)
            except Exception:
                pass

    # 1. Parse manifest
    _progress("Parsing", "Reading Manifest.mbdb …")
    try:
        entries = parse_mbdb(bd / "Manifest.mbdb")
    except Exception as exc:
        stats.add_error(f"FATAL: Cannot parse manifest: {exc}")
        return stats
    _progress("Parsing", f"{len(entries)} entries found", 1.0)

    file_entries = [e for e in entries if e.is_file]
    present = sum(1 for e in file_entries if _find_backup_file(bd, e.sha1) is not None)
    log.info("Manifest: %d entries, %d files (%d present)", len(entries), len(file_entries), present)

    # Filter out raw tasks if not requested
    _RAW_NAMES = {"Raw Databases", "Plists"}
    media_tasks = [
        (n, f) for n, f in _MEDIA_TASKS if include_raw or n not in _RAW_NAMES
    ]
    db_tasks = list(_DB_TASKS)
    all_tasks = media_tasks + db_tasks
    total_tasks = len(all_tasks) + (1 if include_raw else 0)  # +1 for manifest report
    done_tasks = 0

    # Per-file progress callback for large extractors
    def _on_file(category: str, file_count: int):
        _progress("Extracting", f"{category} ({file_count} files)", done_tasks / total_tasks)

    # 2. Media tasks — run sequentially so progress updates after each one.
    #    (Parallel file copies to the *same* disk rarely help and caused the
    #    UI to freeze at ~50 % while Camera Roll finished.)
    for name, func in media_tasks:
        _progress("Extracting", name, done_tasks / total_tasks)
        try:
            count = func(entries=entries, backup_dir=bd, out=od, temp_dir=tmp, on_file=_on_file)
            stats.set(name, count)
            log.info("  %s: %d", name, count)
        except Exception as exc:
            stats.add_error(f"{name}: {exc}")
            log.error("  %s FAILED: %s", name, exc, exc_info=True)
        done_tasks += 1
        _progress("Extracting", name, done_tasks / total_tasks)

    # 3. Database tasks
    for name, func in db_tasks:
        try:
            count = func(entries=entries, backup_dir=bd, out=od, temp_dir=tmp)
            stats.set(name, count)
            log.info("  %s: %d", name, count)
        except Exception as exc:
            stats.add_error(f"{name}: {exc}")
            log.error("  %s FAILED: %s", name, exc, exc_info=True)
        done_tasks += 1
        _progress("Extracting", name, done_tasks / total_tasks)

    # 4. Manifest report (only when raw data is included)
    if include_raw:
        _progress("Reporting", "Generating manifest …")
        try:
            _generate_manifest(entries=entries, backup_dir=bd, out=od)
        except Exception as exc:
            stats.add_error(f"Manifest report: {exc}")
        done_tasks += 1
    _progress("Done", f"Extracted {stats.grand_total} items", 1.0)

    # Cleanup
    shutil.rmtree(tmp, ignore_errors=True)
    return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _auto_detect_backup(base: str = ".") -> Optional[str]:
    """Try to find a backup folder in *base* or its immediate children."""
    for candidate in [base] + [
        os.path.join(base, d) for d in os.listdir(base)
        if os.path.isdir(os.path.join(base, d))
    ]:
        if os.path.isfile(os.path.join(candidate, "Manifest.mbdb")):
            return candidate
    return None


def cli_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="iOS 5/6 Backup Extractor — extract media, messages, contacts, notes and more.",
    )
    parser.add_argument(
        "backup_dir", nargs="?", default=None,
        help="Path to the iTunes backup folder containing Manifest.mbdb (auto-detected if omitted)",
    )
    parser.add_argument(
        "output_dir", nargs="?", default=None,
        help="Destination folder for extracted data (default: ./extracted)",
    )
    parser.add_argument("-w", "--workers", type=int, default=4, help="Thread pool size (default: 4)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    # Resolve backup dir
    backup_dir = args.backup_dir
    if backup_dir is None:
        backup_dir = _auto_detect_backup()
        if backup_dir is None:
            print("ERROR: Could not auto-detect a backup folder. Specify it as the first argument.")
            return 1

    ok, msg = validate_backup(backup_dir)
    if not ok:
        print(f"ERROR: {msg}")
        return 1

    output_dir = args.output_dir or os.path.join(os.path.dirname(os.path.abspath(backup_dir)), "extracted")

    # Header
    print("=" * 70)
    print("  iOS 6 Backup Extractor  v" + __version__)
    print("=" * 70)
    info = get_device_info(backup_dir)
    if info:
        print(f"\n  Device : {info.get('device','')} ({info.get('model','')})")
        print(f"  Name   : {info.get('name','')}")
        print(f"  iOS    : {info.get('ios_version','')} ({info.get('build','')})")
        print(f"  Serial : {info.get('serial','')}")
    print(f"\n  Backup : {os.path.abspath(backup_dir)}")
    print(f"  Output : {os.path.abspath(output_dir)}")
    print()

    t0 = time.time()

    def _cli_progress(phase, detail, frac):
        if frac is not None:
            pct = int(frac * 100)
            bar = "#" * (pct // 2) + "-" * (50 - pct // 2)
            print(f"\r  [{bar}] {pct:3d}%  {phase}: {detail:<40}", end="", flush=True)
        else:
            print(f"  {phase}: {detail}")

    stats = run_extraction(backup_dir, output_dir, max_workers=args.workers, progress=_cli_progress)
    elapsed = time.time() - t0

    print("\n")
    print("=" * 70)
    print("  EXTRACTION COMPLETE")
    print("=" * 70)
    print(f"\n  {'Category':<25} {'Count':>8}")
    print(f"  {'-' * 35}")
    for cat, cnt in stats.totals.items():
        print(f"  {cat:<25} {cnt:>8}")
    print(f"  {'-' * 35}")
    print(f"  {'TOTAL':<25} {stats.grand_total:>8}")
    print(f"\n  Time: {elapsed:.1f}s")

    if stats.errors:
        print(f"\n  Errors ({len(stats.errors)}):")
        for e in stats.errors:
            print(f"    - {e}")

    print(f"\n  Output: {os.path.abspath(output_dir)}")
    return 0


if __name__ == "__main__":
    sys.exit(cli_main())
