import struct


class FAT32Recovery:

    @staticmethod
    def analyze_deleted_entries(drive_path: str):
        """
        Read-only FAT32 deleted-entry analysis.
        Does NOT modify the USB drive.
        """

        device = rf"\\.\{drive_path.rstrip(':\\')}:"

        with open(device, "rb") as f:
            boot = f.read(512)

            bytes_per_sector = struct.unpack_from(
                "<H", boot, 11
            )[0]

            sectors_per_cluster = boot[13]

            reserved_sectors = struct.unpack_from(
                "<H", boot, 14
            )[0]

            fat_count = boot[16]

            fat_size = struct.unpack_from(
                "<I", boot, 36
            )[0]

            root_cluster = struct.unpack_from(
                "<I", boot, 44
            )[0]

            first_data_sector = (
                reserved_sectors
                + fat_count * fat_size
            )

            root_sector = (
                first_data_sector
                + (root_cluster - 2)
                * sectors_per_cluster
            )

            root_offset = (
                root_sector * bytes_per_sector
            )

            cluster_size = (
                bytes_per_sector
                * sectors_per_cluster
            )

            f.seek(root_offset)

            directory_data = f.read(cluster_size)

        deleted = []
        lfn_parts = []

        for offset in range(0, len(directory_data), 32):
            entry = directory_data[offset:offset + 32]
            if len(entry) < 32 or entry[0] == 0x00:
                continue

            # Long filename entry (Attribute 0x0F)
            if entry[11] == 0x0F:
                name_chars = entry[1:11] + entry[14:26] + entry[28:32]
                try:
                    part = name_chars.decode("utf-16le", errors="ignore").split("\x00")[0]
                    lfn_parts.insert(0, part)
                except Exception:
                    pass
                continue

            attributes = entry[11]
            if attributes & 0x08:  # Volume label
                lfn_parts = []
                continue

            is_deleted = (entry[0] == 0xE5)
            first_cluster_low = struct.unpack_from("<H", entry, 26)[0]
            first_cluster_high = struct.unpack_from("<H", entry, 20)[0]
            first_cluster = (first_cluster_high << 16) | first_cluster_low
            file_size = struct.unpack_from("<I", entry, 28)[0]

            raw_name = entry[:8].decode("latin-1", errors="replace").strip()
            raw_ext = entry[8:11].decode("latin-1", errors="replace").strip()
            full_name = "".join(lfn_parts) if lfn_parts else f"{raw_name}.{raw_ext}".strip(".")
            lfn_parts = []

            if is_deleted:
                deleted.append({
                    "directoryOffset": offset,
                    "name": full_name,
                    "shortName": f"{raw_name}.{raw_ext}",
                    "firstCluster": first_cluster,
                    "size": file_size,
                    "isDir": bool(attributes & 0x10),
                    "attributes": hex(attributes)
                })

        return {
            "filesystem": "FAT32",
            "bytesPerSector": bytes_per_sector,
            "sectorsPerCluster": sectors_per_cluster,
            "deletedEntries": deleted
        }

    @staticmethod
    def read_deleted_file(
        drive_path: str,
        first_cluster: int,
        file_size: int
    ):
        """
        Read-only attempt to reconstruct a deleted FAT32 file.

        IMPORTANT:
        This function only reads the USB.
        It does not modify the filesystem.
        """

        device = rf"\\.\{drive_path.rstrip(':\\')}:"

        with open(device, "rb") as f:

            boot = f.read(512)

            bytes_per_sector = struct.unpack_from(
                "<H", boot, 11
            )[0]

            sectors_per_cluster = boot[13]

            reserved_sectors = struct.unpack_from(
                "<H", boot, 14
            )[0]

            fat_count = boot[16]

            fat_size = struct.unpack_from(
                "<I", boot, 36
            )[0]

            cluster_size = (
                bytes_per_sector
                * sectors_per_cluster
            )

            first_data_sector = (
                reserved_sectors
                + fat_count * fat_size
            )

            fat_offset = (
                reserved_sectors
                * bytes_per_sector
            )

            data = bytearray()

            cluster = first_cluster

            visited = set()

            while (
                cluster >= 2
                and len(data) < file_size
                and cluster not in visited
            ):

                visited.add(cluster)

                # Convert cluster number
                # into physical byte offset.
                data_sector = (
                    first_data_sector
                    + (cluster - 2)
                    * sectors_per_cluster
                )

                data_offset = (
                    data_sector
                    * bytes_per_sector
                )

                # Read cluster data.
                f.seek(data_offset)

                chunk = f.read(cluster_size)

                if not chunk:
                    break

                data.extend(chunk)

                # ---------------------------------
                # Read next FAT32 cluster
                # ---------------------------------

                fat_entry_offset = (
                    fat_offset
                    + cluster * 4
                )

                # Align FAT read to sector boundary.
                fat_sector_offset = (
                    fat_entry_offset
                    // bytes_per_sector
                ) * bytes_per_sector

                fat_entry_inside_sector = (
                    fat_entry_offset
                    - fat_sector_offset
                )

                f.seek(fat_sector_offset)

                fat_sector = f.read(
                    bytes_per_sector
                )

                if len(fat_sector) != bytes_per_sector:
                    break

                if (
                    fat_entry_inside_sector + 4
                    > len(fat_sector)
                ):
                    break

                raw_next = fat_sector[
                    fat_entry_inside_sector:
                    fat_entry_inside_sector + 4
                ]

                next_cluster = (
                    struct.unpack(
                        "<I",
                        raw_next
                    )[0]
                    & 0x0FFFFFFF
                )

                # FAT32 end-of-chain.
                if next_cluster >= 0x0FFFFFF8:
                    break

                # Invalid/free cluster.
                if next_cluster < 2:
                    break

                cluster = next_cluster

        return bytes(data[:file_size])


if __name__ == "__main__":

    result = FAT32Recovery.analyze_deleted_entries("E:")

    print(
        "Filesystem:",
        result["filesystem"]
    )

    print(
        "Deleted candidates:",
        len(result["deletedEntries"])
    )

    for item in result["deletedEntries"]:

        print(
            item["name"],
            "| cluster:",
            item["firstCluster"],
            "| size:",
            item["size"],
            "| offset:",
            item["directoryOffset"]
        )