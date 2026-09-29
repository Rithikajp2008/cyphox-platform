import struct
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

drive = r"\\.\E:"
try:
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
        ro = (fds + (rc - 2) * spc) * bps
        f.seek((ro // 512) * 512)
        rd = f.read(csz)
        
        deleted_files = []
        lfn = []

        for off in range(0, len(rd), 32):
            ent = rd[off:off+32]
            if len(ent) < 32 or ent[0] == 0:
                continue

            if ent[11] == 0x0F:
                try:
                    p = (ent[1:11] + ent[14:26] + ent[28:32]).decode('utf-16le', errors='ignore').split('\x00')[0]
                    lfn.insert(0, p)
                except Exception:
                    pass
                continue

            if ent[0] == 0xE5:
                rn = ent[:8].decode('latin-1', errors='replace').strip()
                re = ent[8:11].decode('latin-1', errors='replace').strip()
                fn = ''.join(lfn) if lfn else f'{rn}.{re}'.strip('.')
                lfn = []
                cl_lo = struct.unpack_from('<H', ent, 26)[0]
                cl_hi = struct.unpack_from('<H', ent, 20)[0]
                cluster = (cl_hi << 16) | cl_lo
                size = struct.unpack_from('<I', ent, 28)[0]
                is_dir = bool(ent[11] & 0x10)
                
                raw_time = struct.unpack_from("<H", ent, 22)[0]
                raw_date = struct.unpack_from("<H", ent, 24)[0]
                date_val = (raw_date << 16) | raw_time
                
                # Exclude shortcuts, lock files, and empty entries
                fn_lower = fn.lower()
                if (not fn.startswith('~$') 
                    and not fn_lower.endswith('.lnk') 
                    and not fn_lower.endswith('.tmp')
                    and not is_dir 
                    and size > 512
                    and not any(c in fn for c in ['\x00', 'ÿ'])):
                    deleted_files.append({
                        "name": fn,
                        "cluster": cluster,
                        "size": size,
                        "date_val": date_val
                    })
            else:
                lfn = []

        if deleted_files:
            deleted_files.sort(key=lambda x: x["date_val"], reverse=True)
            top = deleted_files[0]
            
            to = (fds + (top["cluster"] - 2) * spc) * bps
            diff = to - ((to // 512) * 512)
            f.seek((to // 512) * 512)
            rt = max(512, ((top["size"] + diff + 511) // 512) * 512)
            data = f.read(rt)[diff : diff + top["size"]]
            
            dp = os.path.join(r"C:\Users\Rithika\Desktop", top["name"])
            with open(dp, "wb") as out_f:
                out_f.write(data)
                
            print(f"{top['name']}:::{top['size']}:::{dp}")
        else:
            sys.exit(1)
except Exception as err:
    sys.exit(1)
