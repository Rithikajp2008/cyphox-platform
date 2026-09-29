import struct, os, sys, json
from datetime import datetime

JOURNAL_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "fat32_journal.json")

def load_journal():
    if os.path.exists(JOURNAL_FILE):
        try:
            with open(JOURNAL_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_journal(journal):
    try:
        os.makedirs(os.path.dirname(JOURNAL_FILE), exist_ok=True)
        with open(JOURNAL_FILE, "w", encoding="utf-8") as f:
            json.dump(journal, f, indent=2)
    except:
        pass

def resolve_real_cluster(f, cl_lo, cl_hi, ext, fds, spc, bps):
    if cl_hi > 0:
        return (cl_hi << 16) | cl_lo
    
    sigs = {
        'pdf': b'%PDF',
        'pptx': b'PK\x03\x04',
        'docx': b'PK\x03\x04',
        'xlsx': b'PK\x03\x04',
        'zip': b'PK\x03\x04',
        'jpg': b'\xff\xd8\xff',
        'png': b'\x89PNG',
        'mp4': b'ftyp',
        'doc': b'\xd0\xcf\x11\xe0'
    }
    target_sig = sigs.get(ext.lower(), b'')
    if target_sig:
        for hi in range(0, 48):
            cand = (hi << 16) | cl_lo
            if cand < 2: continue
            try:
                ro = (fds + (cand - 2) * spc) * bps
                diff = ro - ((ro // 512) * 512)
                f.seek((ro // 512) * 512)
                data = f.read(512 + diff)[diff : diff + 32]
                if target_sig in data[:20]:
                    return cand
            except:
                pass
    return cl_lo

def scan_fat32_drive(drive_letter="E"):
    drive_path = f"\\\\.\\{drive_letter}:"
    results = []
    journal = load_journal()
    journal_changed = False
    
    try:
        with open(drive_path, "rb") as f:
            boot = f.read(512)
            bps = struct.unpack_from("<H", boot, 11)[0]
            spc = boot[13]
            res = struct.unpack_from("<H", boot, 14)[0]
            fc = boot[16]
            fsz = struct.unpack_from("<I", boot, 36)[0]
            rc = struct.unpack_from("<I", boot, 44)[0]
            fds = res + fc * fsz
            csz = bps * spc
            ro = (fds + (rc - 2) * spc) * bps
            f.seek((ro // 512) * 512)
            rd = f.read(csz)
            
            lfn = []
            for off in range(0, len(rd), 32):
                ent = rd[off:off+32]
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
                is_dir = bool(ent[11] & 0x10)
                rn = ent[:8].decode('latin-1', errors='replace').strip()
                re = ent[8:11].decode('latin-1', errors='replace').strip()
                fn = ''.join(lfn) if lfn else f"{rn}.{re}".strip('.')
                lfn = []
                
                if not is_del:
                    continue
                
                cl_lo = struct.unpack_from('<H', ent, 26)[0]
                cl_hi = struct.unpack_from('<H', ent, 20)[0]
                size = struct.unpack_from('<I', ent, 28)[0]
                raw_time = struct.unpack_from('<H', ent, 22)[0]
                raw_date = struct.unpack_from('<H', ent, 24)[0]
                
                cleaned_name = "".join(c for c in fn if c.isprintable() and c not in '\x00\xff\ufffd')
                if not cleaned_name or cleaned_name.startswith('~$') or cleaned_name.endswith('.lnk'):
                    continue
                
                ext = cleaned_name.split('.')[-1] if '.' in cleaned_name else ''
                real_cluster = resolve_real_cluster(f, cl_lo, cl_hi, ext, fds, spc, bps)
                
                j_key = f"{drive_letter}_{cleaned_name}_{size}"
                if j_key in journal:
                    dt_str = journal[j_key].get("deletedAt")
                    ts = journal[j_key].get("deletedTimestamp", 0)
                else:
                    year = ((raw_date >> 9) & 0x7F) + 1980
                    month = max(1, min(12, (raw_date >> 5) & 0x0F))
                    day = max(1, min(31, raw_date & 0x1F))
                    hour = min(23, (raw_time >> 11) & 0x1F)
                    minute = min(59, (raw_time >> 5) & 0x3F)
                    second = min(59, (raw_time & 0x1F) * 2)
                    try:
                        dt = datetime(year, month, day, hour, minute, second)
                        dt_str = dt.isoformat()
                        ts = dt.timestamp() * 1000
                    except:
                        dt_str = datetime.now().isoformat()
                        ts = datetime.now().timestamp() * 1000
                
                results.append({
                    "id": f"usb_{drive_letter}_{real_cluster}_{off}",
                    "name": cleaned_name,
                    "isDir": is_dir,
                    "originalPath": f"{drive_letter}:\\{cleaned_name}",
                    "cluster": real_cluster,
                    "size": size,
                    "deletedAt": dt_str,
                    "deletedTimestamp": int(ts),
                    "source": "USB_FAT32_DRIVE",
                    "driveLetter": drive_letter,
                    "tableOffset": off
                })
        
        if journal_changed:
            save_journal(journal)
            
        results.sort(key=lambda x: x["deletedTimestamp"], reverse=True)
    except Exception as e:
        pass
    return results

def restore_fat32_item(drive_letter, cluster, size, is_dir, out_path):
    drive_path = f"\\\\.\\{drive_letter}:"
    try:
        if is_dir:
            os.makedirs(out_path, exist_ok=True)
            if cluster >= 2:
                with open(drive_path, "rb") as f:
                    boot = f.read(512)
                    bps = struct.unpack_from("<H", boot, 11)[0]
                    spc = boot[13]
                    res = struct.unpack_from("<H", boot, 14)[0]
                    fc = boot[16]
                    fsz = struct.unpack_from("<I", boot, 36)[0]
                    fds = res + fc * fsz
                    csz = bps * spc
                    ro = (fds + (cluster - 2) * spc) * bps
                    f.seek((ro // 512) * 512)
                    rd = f.read(csz)
                    
                    lfn = []
                    for off in range(0, len(rd), 32):
                        ent = rd[off:off+32]
                        if len(ent) < 32 or ent[0] == 0: continue
                        if ent[11] == 0x0F:
                            try:
                                lfn.insert(0, (ent[1:11] + ent[14:26] + ent[28:32]).decode('utf-16le', errors='ignore').split('\x00')[0])
                            except: pass
                            continue
                        sub_del = (ent[0] == 0xE5)
                        sub_dir = bool(ent[11] & 0x10)
                        rn = ent[:8].decode('latin-1', errors='replace').strip()
                        re = ent[8:11].decode('latin-1', errors='replace').strip()
                        sub_fn = ''.join(lfn) if lfn else f"{rn}.{re}".strip('.')
                        lfn = []
                        if sub_fn in ['.', '..'] or not sub_fn:
                            continue
                        cl_lo = struct.unpack_from('<H', ent, 26)[0]
                        cl_hi = struct.unpack_from('<H', ent, 20)[0]
                        sub_cluster = (cl_hi << 16) | cl_lo
                        sub_size = struct.unpack_from('<I', ent, 28)[0]
                        if not sub_dir and sub_size > 0 and sub_cluster >= 2:
                            sub_out = os.path.join(out_path, sub_fn)
                            try:
                                sub_ro = (fds + (sub_cluster - 2) * spc) * bps
                                f.seek((sub_ro // 512) * 512)
                                diff = sub_ro - ((sub_ro // 512) * 512)
                                bytes_needed = ((sub_size + diff + 511) // 512) * 512
                                sub_data = f.read(bytes_needed)[diff : diff + sub_size]
                                with open(sub_out, "wb") as sf:
                                    sf.write(sub_data)
                            except:
                                pass
            return {"success": True, "path": out_path, "isDir": True}
        else:
            if size <= 0 or cluster < 2:
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f:
                    pass
                return {"success": True, "path": out_path, "bytes": 0}
            
            with open(drive_path, "rb") as f:
                boot = f.read(512)
                bps = struct.unpack_from("<H", boot, 11)[0]
                spc = boot[13]
                res = struct.unpack_from("<H", boot, 14)[0]
                fc = boot[16]
                fsz = struct.unpack_from("<I", boot, 36)[0]
                fds = res + fc * fsz
                csz = bps * spc
                ro = (fds + (cluster - 2) * spc) * bps
                diff = ro - ((ro // 512) * 512)
                f.seek((ro // 512) * 512)
                
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                
                # Stream write in chunks (supports files of any size, from 1KB to 10GB+)
                bytes_left = size
                chunk_size = 2 * 1024 * 1024 # 2MB chunks
                
                # First chunk accounts for sector diff offset
                first_needed = max(512, ((min(bytes_left, chunk_size) + diff + 511) // 512) * 512)
                first_data = f.read(first_needed)[diff : diff + min(bytes_left, chunk_size)]
                
                with open(out_path, "wb") as out_f:
                    out_f.write(first_data)
                    bytes_left -= len(first_data)
                    
                    while bytes_left > 0:
                        cur_read = min(bytes_left, chunk_size)
                        aligned_read = ((cur_read + 511) // 512) * 512
                        raw_buf = f.read(aligned_read)[:cur_read]
                        if not raw_buf:
                            break
                        out_f.write(raw_buf)
                        bytes_left -= len(raw_buf)
                
                return {"success": True, "path": out_path, "bytes": size}
    except Exception as e:
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--restore":
        d_let = sys.argv[2]
        cl = int(sys.argv[3])
        sz = int(sys.argv[4])
        is_d = sys.argv[5].lower() in ['1', 'true', 'yes']
        out_p = sys.argv[6]
        res = restore_fat32_item(d_let, cl, sz, is_d, out_p)
        print(json.dumps(res))
    else:
        letter = sys.argv[1] if len(sys.argv) > 1 else "E"
        items = scan_fat32_drive(letter)
        print(json.dumps(items))
