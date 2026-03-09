# iOS 6 Backup Extractor

A Python tool that extracts and organizes data from **unencrypted iOS 5/6 iTunes backups** — the kind that use `Manifest.mbdb` (not the newer `Manifest.db` format from iOS 10+).

Recovers photos, videos, messages, contacts, notes, calendar events, Safari bookmarks/history, music, voicemail, app data, WiFi passwords, and more into neatly organized, human-readable folders and files.

## Features

- **Full MBDB parser** — reads the binary `Manifest.mbdb` format used by iOS 5 and 6
- **Camera Roll & Photos** — JPG, PNG, MOV, MP4, etc.
- **SMS / iMessage** — conversations exported as text, CSV, and per-contact files
- **Contacts** — TXT, CSV, and VCF (vCard) formats
- **Notes** — with HTML-to-text conversion
- **Calendar events** — TXT and CSV
- **Safari** — bookmarks and browsing history
- **Music & Voice Memos** — audio files (MP3, M4A, etc.)
- **App data** — databases, plists, media from installed apps
- **WiFi passwords** — saved network SSIDs
- **Voicemail** — audio files and metadata
- **Settings / Plists** — important system preference files as JSON
- **Raw databases** — all `.db` / `.sqlite` files copied for manual inspection
- **Full manifest report** — CSV of every file in the backup with domain, path, size, and existence check
- **Multithreaded** — media files are copied in parallel via a configurable thread pool
- **Failsafe** — every extractor is isolated; one failure doesn't stop the rest
- **GUI** — simple tkinter interface with file browser, progress bar, and scrolling log
- **CLI** — full command-line interface with auto-detection

## Screenshots

| GUI | CLI |
|-----|-----|
| *(run `python gui.py` to see)* | *(run `python extract_backup.py`)* |

## Requirements

- **Python 3.8+** (tested with 3.12)
- **No external dependencies** — uses only the Python standard library (`tkinter`, `sqlite3`, `plistlib`, `hashlib`, `struct`, `csv`, `json`, `shutil`, `concurrent.futures`, etc.)

> **Note:** `tkinter` ships with most Python installations. On Linux you may need to install it separately (e.g., `sudo apt install python3-tk`).

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/ios6-backup-extractor.git
cd ios6-backup-extractor
```

No `pip install` needed — it's pure stdlib Python.

## Usage

### GUI

```bash
python gui.py
```

1. Click **Browse** to select your backup folder (the one containing `Manifest.mbdb`)
2. Optionally change the output folder
3. Click **Extract**
4. Watch the progress bar and log

### CLI

```bash
# Explicit paths
python extract_backup.py /path/to/backup /path/to/output

# Auto-detect backup in the current directory
python extract_backup.py

# Verbose logging + 8 worker threads
python extract_backup.py /path/to/backup -v -w 8
```

```
Usage: extract_backup.py [-h] [-w WORKERS] [-v] [--version] [backup_dir] [output_dir]

positional arguments:
  backup_dir            Path to the iTunes backup folder containing Manifest.mbdb
  output_dir            Destination folder for extracted data (default: ./extracted)

options:
  -h, --help            show help message and exit
  -w, --workers         Thread pool size (default: 4)
  -v, --verbose         Verbose logging
  --version             show program's version number and exit
```

## Output Structure

```
extracted/
├── Photos_and_Videos/
│   ├── Camera_Roll/
│   └── PhotoData/
├── Messages/
│   ├── all_messages.txt
│   ├── all_messages.csv
│   ├── conversations/
│   │   ├── +1234567890.txt
│   │   └── ...
│   └── attachments/
├── Contacts/
│   ├── all_contacts.txt
│   ├── all_contacts.csv
│   └── all_contacts.vcf
├── Notes/
│   ├── all_notes.txt
│   └── individual/
├── Calendar/
│   ├── calendar_events.txt
│   └── calendar_events.csv
├── Safari/
│   ├── bookmarks.txt
│   └── history.txt
├── Music/
├── Voice_Memos/
├── Videos/
├── Wallpapers/
├── Voicemail/
├── WiFi/
│   └── wifi_networks.txt
├── Apps/
│   ├── _installed_apps.txt
│   └── com.example.app/
├── Settings_Plists/
├── Call_History/
├── _raw_databases/
└── _manifest/
    ├── full_file_manifest.csv
    ├── domain_summary.txt
    └── missing_files.txt
```

## How iOS 5/6 Backups Work

iTunes backups from this era store each file as a SHA-1 hash of `"{domain}-{path}"`. The `Manifest.mbdb` file is a custom binary format that maps these hashes back to their original locations on the device.

This tool:
1. Parses `Manifest.mbdb` to build a full file index
2. Uses the SHA-1 hash to locate each blob in the backup folder
3. Copies and organizes files by category
4. Opens SQLite databases (SMS, Contacts, Calendar, etc.) to extract structured data into readable formats

## Compatibility

| iOS Version | Manifest Format | Supported |
|-------------|-----------------|-----------|
| iOS 3–4     | `Manifest.mbdb` | ✅ Should work |
| iOS 5–6     | `Manifest.mbdb` | ✅ Tested |
| iOS 7–9     | `Manifest.mbdb` | ✅ Should work |
| iOS 10+     | `Manifest.db`   | ❌ Different format |

## Contributing

Pull requests are welcome. For major changes, please open an issue first.

## License

[MIT](LICENSE)
