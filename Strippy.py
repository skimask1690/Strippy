import argparse
import pefile
import os

# ——— CLI ———

def main():
    parser = argparse.ArgumentParser(
        description="Strippy: Remove debug information, relocations, IAT, RDATA padding, resource sections, and overlay data."
    )
    parser.add_argument("pe_file", help="Path to the input PE file")
    parser.add_argument("-d", "--debug", action="store_true", help="Remove debug directory")
    parser.add_argument("-l", "--reloc", action="store_true", help="Remove relocation section")
    parser.add_argument("-I", "--iat", action="store_true", help="Clear IAT directory")
    parser.add_argument("-O", "--overlay", action="store_true", help="Truncate overlay data")
    parser.add_argument("-R", "--rdata", action="store_true", help="Trim raw size to virtual size in read-only data sections")
    parser.add_argument("-r", "--rsrc", action="store_true", help="Remove resource section")
    parser.add_argument("-a", "--all", action="store_true", help="Apply all safe modifications")
    parser.add_argument("-o", "--output", required=True, help="Path for the output file")
    args = parser.parse_args()

    if not any([args.debug, args.reloc, args.iat, args.overlay, args.rdata, args.rsrc, args.all]):
        print("[-] No stripping options provided.")
        return

    if args.all:
        # Apply all cleanup flags if `--all` is specified.
        args.debug = args.iat = args.overlay = args.rdata = args.rsrc = True

    process_pe(args.pe_file, args)

# ——— Processing Routine ———

def process_pe(path, args):
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError:
        print("[-] Invalid PE file format.")
        return

    arch = {0x10b: "32-bit", 0x20b: "64-bit"}.get(pe.OPTIONAL_HEADER.Magic, "Unknown")
    print(f"[+] Loaded {arch} executable.")

    # Check if the file is a .NET assembly by examining the CLR header (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
    dotnet_flag = False
    clr_entry_index = pefile.DIRECTORY_ENTRY.get('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR')
    if clr_entry_index is not None:
        clr_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[clr_entry_index]
        if clr_entry.VirtualAddress != 0:
            dotnet_flag = True
            # Print message if any relevant cleanup flag is enabled
            if args.all or args.reloc or args.rdata:
                print("[*] Detected .NET assembly.")

    modified = False
    if args.debug:
        modified |= strip_debug(pe)
    if args.reloc:
        if dotnet_flag:
            print("[*] Skipping relocation removal for .NET assembly.")
        else:
            modified |= strip_reloc(pe)
    if args.iat:
        modified |= strip_iat(pe)
    if args.rdata:
        if dotnet_flag:
            print("[*] Skipping RDATA padding removal for .NET assembly.")
        else:
            modified |= strip_padding(pe)
    if args.rsrc and not args.all:  # Skip resource section removal if `-a` is enabled
        modified |= strip_rsrc(pe)

    data = pe.write()
    sections = list(pe.sections)
    pe.close()

    if args.overlay:
        data, changed = truncate_overlay(data, sections)
        modified |= changed

    if not modified:
        print("[*] No changes were made.")
        return

    with open(args.output, 'wb') as f:
        f.write(data)
    print(f"[+] Modified PE file saved to: {args.output}")

# ——— Helper Functions ———

def strip_debug(pe):
    if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        print("[-] No debug directory found.")
        return False
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']
    ]
    entry.VirtualAddress = entry.Size = 0
    for debug in pe.DIRECTORY_ENTRY_DEBUG:
        offset = debug.struct.get_file_offset()
        pe.set_bytes_at_offset(offset, b'\x00' * debug.struct.sizeof())
    print(f"[+] Removed {len(pe.DIRECTORY_ENTRY_DEBUG)} debug entries.")
    return True

def strip_reloc(pe):
    # Only support relocation stripping for 32-bit format.
    if pe.OPTIONAL_HEADER.Magic != 0x10b:
        print("[-] Only 32-bit format is supported for relocation stripping.")
        return False

    reloc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']
    ]
    if reloc.VirtualAddress == 0:
        print("[-] No relocation directory found.")
        return False

    section = next(
        (s for s in pe.sections
         if s.VirtualAddress <= reloc.VirtualAddress < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)),
        None
    )
    if not section:
        print("[-] Relocation section could not be located.")
        return False

    section.Name = b'\x00' * 8
    reloc.VirtualAddress = reloc.Size = 0
    remove_section(pe, section)

    print("[+] Relocation section removed successfully.")
    return True

def strip_iat(pe):
    idx = pefile.DIRECTORY_ENTRY.get('IMAGE_DIRECTORY_ENTRY_IAT')
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
    if directory.VirtualAddress == 0:
        print("[-] IAT directory not found.")
        return False
    directory.VirtualAddress = directory.Size = 0
    print("[+] IAT directory entry cleared.")
    return True

def strip_padding(pe):
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000
    changed = False

    for s in pe.sections:
        if (s.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA and not (s.Characteristics & IMAGE_SCN_MEM_WRITE)):
            virt_size = s.Misc_VirtualSize
            raw_size = s.SizeOfRawData

            if raw_size > virt_size:
                name = s.Name.rstrip(b'\x00').decode(errors='ignore')
                print(f"[+] Trimming {name} section: {raw_size} → {virt_size} bytes")
                s.SizeOfRawData = virt_size
                changed = True

    if not changed:
        print("[*] No padding found in read-only data sections.")
    return changed

def strip_rsrc(pe):
    rsrc_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
    ]
    if rsrc_entry.VirtualAddress == 0:
        print("[-] No resource directory found.")
        return False

    section = next(
        (s for s in pe.sections
         if s.VirtualAddress <= rsrc_entry.VirtualAddress < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)),
        None
    )
    if not section:
        print("[-] Resource section could not be located.")
        return False

    section.Name = b'\x00' * 8
    rsrc_entry.VirtualAddress = rsrc_entry.Size = 0
    remove_section(pe, section)

    print("[+] Resource section removed successfully.")
    return True

def remove_section(pe, section):
    idx = pe.sections.index(section)
    pe.sections.pop(idx)
    pe.FILE_HEADER.NumberOfSections -= 1

    for s in pe.sections[idx:]:
        if s.PointerToRawData > section.PointerToRawData:
            s.PointerToRawData -= section.SizeOfRawData
        if s.VirtualAddress > section.VirtualAddress:
            s.VirtualAddress -= section.Misc_VirtualSize

    max_va = max(s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections)
    aligned = (max_va + pe.OPTIONAL_HEADER.SectionAlignment - 1) & ~(pe.OPTIONAL_HEADER.SectionAlignment - 1)
    pe.OPTIONAL_HEADER.SizeOfImage = aligned

def truncate_overlay(data, sections):
    end = max(s.PointerToRawData + s.SizeOfRawData for s in sections)
    if len(data) > end:
        print(f"[+] Truncating overlay: {len(data)} → {end} bytes")
        return data[:end], True
    print("[*] No overlay data to truncate.")
    return data, False

# ——— Entry Point ———

if __name__ == "__main__":
    main()
