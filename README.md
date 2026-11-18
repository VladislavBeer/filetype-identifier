# filetype-identifier
A command-line tool that identifies whether a given file's true type by checking its content signature (magic bytes) and compares it with the filename extension.

The program is safe to point at untrusted files: it opens files in binary mode, reads only the first 4096 bytes, and nothing is ever executed, opened in any other way, or modified.

## How it works

1. The program shorts the filename to take the extension only (`report.pdf.exe -> .exe`) and lowercased.
2. The first 4096 bytes of the file are read.
3. The header is tested against a table of known signatures. Longer signatures are tried first so that shorter signatures cannot spoof their file type.
4. Short or ambiguous signatures (BMP, Windows PE, MP3, MP4 and co.) get a second validation step to avoid false positives on ordinary text.
5. The detected type's allowed extensions are compared with the file's actual extension, and a verdict is printed with the true file type.

![Example output of the scanner](https://github.com/user-attachments/assets/9b15f15a-2615-4f33-ac2d-157e5e279f84)

### Verdicts

| Verdict        | Meaning                                                                                       |
| -------------- | --------------------------------------------------------------------------------------------- |
| `MATCH`        | The detected type is the same as the extension.                                               |
| `MISMATCH`     | The detected type is known, but the extension doesn't belong to it (e.g. a PNG named `.txt`). |
| `NO_EXTENSION` | A known type was detected, but the file has no extension.                                     |
| `UNKNOWN_TYPE` | No signature matched (plain text, empty files, unsupported formats).                          |
| `ERROR`        | The file couldn't be read (e.g. permission denied).                                           |

A summary count is then printed. The exit code is `1` if any file was a `MISMATCH`, otherwise `0`, so the tool can be used in scripts.
## Installation

Python 3.10+ is required. The identifier itself uses only the Python standard library, with no need for additional downloads.

```powershell
git clone https://github.com/VladislavBeer/filetype-identifier
cd filetype-identifier
```

## Tests/Usage

```powershell
python filetype-identifier.py test.png                 # one file
python filetype-identifier.py a.jpg b.exe testFolder   # several files and folders
python filetype-identifier.py -r testFolder            # recurse into subfolders
```

Example output:

```
MATCH         PNG         .png     good.png
MISMATCH      PNG         .txt     sneaky.txt
MISMATCH      Windows PE  .jpg     photo.jpg
UNKNOWN_TYPE  unknown     .txt     notes.txt

MATCH=1, MISMATCH=2, UNKNOWN_TYPE=1
```

To try it on a mismatch, copy any file and give the copy the wrong extension (on Windows, make sure file extensions are visible in File Explorer). The tool only reads the file, so this is safe even with executables.

## Supported types  

| Category      | Types                                                                                    |
| ------------- | ---------------------------------------------------------------------------------------- |
| Images        | PNG, JPEG, GIF, BMP, WebP, HEIC, AVIF                                                    |
| Documents     | PDF, legacy Office (OLE2: `.doc`, `.xls`, `.ppt`, `.msi`, ...)                           |
| Audio / video | MP3, WAV, AVI, MP4 / M4A, MOV, MKV, WebM                                                 |
| Archives      | ZIP (including `.docx`, `.xlsx`, `.pptx`, `.jar`, `.apk`, `.odt`), GZIP, TAR, RAR, 7-Zip |
| Databases     | SQLite (`.sqlite`, `.sqlite3`,`.db`, `.db3`)                                             |
| Executables   | Windows PE (`.exe`, `.dll`, ...), Linux ELF                                              |

## Known limitations

- Doesn't validate, so **matching headers can be forged**.
- **Polyglot files and appended data aren't detected**. A polyglot with an MP3 header named .mp3 gets matched as an MP3.
- **Plain-text formats can't be identified.** Text, CSV and other files without magic bytes have no magic bytes, so their verdict is `UNKNOWN_TYPE`.
- **ZIP-based formats aren't told apart.** Any ZIP is accepted with any ZIP-family extension, so a `.zip` renamed to `.docx` is a `MATCH`.
- **Some old variants are missed.** Pre-POSIX TAR files and DOS-only `.exe` files (no PE header) aren't recognised.
- Permission and filesystem behavior vary by operating system.
