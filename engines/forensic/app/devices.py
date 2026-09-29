from __future__ import annotations
import ctypes
import os
import platform
from pathlib import Path
from typing import Any


def _windows_drive_type(root: str) -> str:
    # https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getdrivetypew
    value = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
    return {
        0: "UNKNOWN", 1: "NO_ROOT", 2: "REMOVABLE", 3: "FIXED",
        4: "REMOTE", 5: "CDROM", 6: "RAMDISK"
    }.get(value, "UNKNOWN")


def _windows_volume(root: str) -> dict[str, Any]:
    label = ctypes.create_unicode_buffer(261)
    fs = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_uint32()
    max_comp = ctypes.c_uint32()
    flags = ctypes.c_uint32()
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root), label, len(label), ctypes.byref(serial),
        ctypes.byref(max_comp), ctypes.byref(flags), fs, len(fs)
    )
    return {
        "label": label.value if ok else None,
        "filesystem": fs.value if ok else None,
        "serial": f"{serial.value:08X}" if ok else None,
    }


def list_devices() -> list[dict[str, Any]]:
    if os.name == "nt":
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        items = []
        for i in range(26):
            if mask & (1 << i):
                root = f"{chr(65+i)}:\\"
                vol = _windows_volume(root)
                try:
                    usage = __import__("shutil").disk_usage(root)
                    total, free = usage.total, usage.free
                except OSError:
                    total = free = None
                items.append({
                    "deviceId": f"DRIVE-{chr(65+i)}",
                    "mountPoint": root,
                    "driveType": _windows_drive_type(root),
                    "filesystem": vol["filesystem"],
                    "volumeLabel": vol["label"],
                    "volumeSerial": vol["serial"],
                    "totalBytes": total,
                    "freeBytes": free,
                    "systemDisk": chr(65+i).upper() == os.environ.get("SystemDrive", "C:")[0].upper(),
                })
        return items
    root = Path("/")
    st = os.statvfs(root)
    return [{
        "deviceId": "POSIX-ROOT", "mountPoint": "/", "driveType": "FIXED",
        "filesystem": None, "volumeLabel": None, "volumeSerial": None,
        "totalBytes": st.f_frsize * st.f_blocks, "freeBytes": st.f_frsize * st.f_bavail,
        "systemDisk": True, "platform": platform.system(),
    }]


def device_for_path(path: str) -> dict[str, Any] | None:
    try:
        resolved = str(Path(path).expanduser().resolve())
    except Exception:
        resolved = path
    if os.name == "nt":
        drive = os.path.splitdrive(resolved)[0].upper()
        return next((d for d in list_devices() if d["mountPoint"].upper().startswith(drive)), None)
    return list_devices()[0]
