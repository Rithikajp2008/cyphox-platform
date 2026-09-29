import struct
import os
import sys
import hashlib

sys.stdout.reconfigure(encoding='utf-8')

drive = r"\\.\E:"
dest_dir = r"C:\Users\Rithika\Desktop\Recovered_Pendrive_Data"
os.makedirs(dest_dir, exist_ok=True)

print("===========================================================", flush=True)
print("  🛡️ CYPHOX ADVANCED FORENSIC RECOVERY ENGINE (SIH26149) 🛡️", flush=True)
print("===========================================================", flush=True)
print(f"Target: {drive} | Output: {dest_dir}\n", flush=True)

with open(drive, "rb") as f:
    boot = f.read(512)
    bps = struct.unpack_from("<H", boot, 11)[0]
    spc = boot[13]
    res = struct.unpack_from("<H", boot, 14)[0]
    fc = boot[16]
    fsz = struct.unpack_from("<I", boot, 36)[0]
    rc = struct.unpack_from("<I", boot, 44)[0]
    fds = res + fc * fsz
    csz = bps * spc

    def get_cluster_offset(cluster_num):
        sector = fds + (cluster_num - 2) * spc
        return sector * bps

    # Read root directory
    offset = get_cluster_offset(rc)
    f.seek((offset // 512) * 512)
    data = f.read(csz)

    lfn = []
    recovered_items = []
    
    print("⚡ Scanning Directory Entries...", flush=True)

    for i in range(0, len(data), 32):
        ent = data[i : i + 32]
        if len(ent) < 32 or ent[0] == 0:
            continue

        if ent[11] == 0x0F:
            try:
                p = (ent[1:11] + ent[14:26] + ent[28:32]).decode('utf-16le', errors='ignore').split('\x00')[0]
                lfn.insert(0, p)
            except:
                pass
            continue

        is_del = (ent[0] == 0xE5)
        rn = ent[:8].decode('latin-1', errors='replace').strip()
        re = ent[8:11].decode('latin-1', errors='replace').strip()
        fn = ''.join(lfn) if lfn else f'{rn}.{re}'.strip('.')
        lfn = []

        sz = struct.unpack_from('<I', ent, 28)[0]
        cl = (struct.unpack_from('<H', ent, 20)[0] << 16) | struct.unpack_from('<H', ent, 26)[0]
        is_dir = bool(ent[11] & 0x10)

        if is_del and not fn.startswith('~$') and not any(c in fn for c in ['\x00', 'ÿ']):
            clean_name = fn.lstrip('å').lstrip('\xe5')
            if not clean_name:
                continue
            if clean_name.lower().endswith('.lnk'):
                continue

            if is_dir:
                folder_path = os.path.join(dest_dir, clean_name)
                os.makedirs(folder_path, exist_ok=True)
                print(f"📁 Recovered Directory: {clean_name}/", flush=True)
                recovered_items.append({
                    "name": f"[DIR] {clean_name}",
                    "size": 0,
                    "path": folder_path
                })
            elif sz > 0 and cl >= 2:
                try:
                    to = get_cluster_offset(cl)
                    diff = to - ((to // 512) * 512)
                    f.seek((to // 512) * 512)

                    file_out_path = os.path.join(dest_dir, clean_name)
                    hasher = hashlib.sha256()

                    # Stream copy in 1MB chunks to be ultra fast!
                    bytes_left = sz
                    first_read = min(bytes_left + diff, 1024 * 1024)
                    first_buf = f.read(first_read)
                    actual_data = first_buf[diff : diff + min(bytes_left, len(first_buf) - diff)]

                    with open(file_out_path, "wb") as out_f:
                        out_f.write(actual_data)
                        hasher.update(actual_data)
                        bytes_left -= len(actual_data)

                        while bytes_left > 0:
                            chunk_sz = min(bytes_left, 1024 * 1024)
                            chunk = f.read(chunk_sz)
                            if not chunk:
                                break
                            out_f.write(chunk)
                            hasher.update(chunk)
                            bytes_left -= len(chunk)

                    sz_str = f"{sz / 1024:.1f} KB" if sz < 1024*1024 else f"{sz / (1024*1024):.2f} MB"
                    print(f"📄 Recovered: {clean_name} ({sz_str})", flush=True)
                    recovered_items.append({
                        "name": clean_name,
                        "size": sz,
                        "path": file_out_path,
                        "sha256": hasher.hexdigest()
                    })
                except Exception as e:
                    print(f"   Error: {e}", flush=True)

print(f"\n===========================================================", flush=True)
print(f"🎉 TOTAL RECOVERED: {len(recovered_items)} FILES & FOLDERS", flush=True)
print(f"📁 Destination: {dest_dir}", flush=True)
print("===========================================================", flush=True)
