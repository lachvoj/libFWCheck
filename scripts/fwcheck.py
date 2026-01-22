#!/usr/bin/env python3
"""
fwcheck.py - PlatformIO post-build script for firmware CRC injection

This script:
1. Reads the compiled firmware binary
2. Locates the .fwcheck section (via linker symbols from ELF)
3. Calculates CRC32 over firmware content (from start to CRC section)
4. Injects magic number and two CRC copies into the .fwcheck section
5. Optionally injects firmware version string (from git describe)

Usage in platformio.ini:
    extra_scripts = post:lib/libFWCheck/scripts/fwcheck.py

Build flags:
    -DFWCHECK_ENABLED              : Enable CRC injection (required)
    -DFWCHECK_USE_HW_CRC           : Use hardware CRC polynomial (0x04C11DB7)
    -DFWCHECK_INCLUDE_FW_VERSION   : Include firmware version string
    -DFWCHECK_FW_VERSION_SIZE=N    : Set version string size (default 32)
    (default)                      : Use software CRC polynomial (0xEDB88320)

Author: libFWCheck
License: MIT
"""

import struct
import os
import sys

# PlatformIO imports
try:
    Import("env", "projenv")
    PLATFORMIO_ENV = True
except:
    PLATFORMIO_ENV = False

# ============================================================================
# Constants
# ============================================================================

# Magic number "FWCH" in little-endian
FWCHECK_MAGIC = 0x48435746

# CRC32 Polynomials
CRC32_POLY_HW = 0x04C11DB7   # STM32 hardware CRC (normal form)
CRC32_POLY_SW = 0xEDB88320   # Standard CRC32 (bit-reversed form)

# Section size: magic(4) + CRC1(4) + CRC2(4) = 12 bytes
FWCHECK_SECTION_SIZE = 12

# Default FW version string size (including null terminator)
FWCHECK_FW_VERSION_SIZE_DEFAULT = 32


# ============================================================================
# CRC32 Calculation Functions
# ============================================================================

def crc32_sw(data: bytes) -> int:
    """
    Calculate CRC32 using standard polynomial 0xEDB88320 (bit-reversed).
    This matches the software implementation in FWCheck.c
    
    Args:
        data: Input data bytes
        
    Returns:
        CRC32 value (32-bit unsigned)
    """
    crc = 0xFFFFFFFF
    
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ CRC32_POLY_SW
            else:
                crc >>= 1
    
    return crc ^ 0xFFFFFFFF


def crc32_hw(data: bytes) -> int:
    """
    Calculate CRC32 using STM32 hardware polynomial 0x04C11DB7 (normal form).
    This matches the hardware CRC peripheral in STM32F1.
    
    The STM32 CRC peripheral:
    - Processes 32-bit words
    - Uses polynomial 0x04C11DB7
    - Initial value 0xFFFFFFFF
    - No output XOR
    
    Args:
        data: Input data bytes (will be padded to 4-byte boundary)
        
    Returns:
        CRC32 value (32-bit unsigned)
    """
    # Pad data to 4-byte boundary
    padding_needed = (4 - (len(data) % 4)) % 4
    if padding_needed:
        data = data + bytes(padding_needed)
    
    crc = 0xFFFFFFFF
    
    # Process 32-bit words (little-endian)
    for i in range(0, len(data), 4):
        word = struct.unpack('<I', data[i:i+4])[0]
        crc ^= word
        
        for _ in range(32):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ CRC32_POLY_HW) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    
    return crc


# ============================================================================
# FW Version Extraction
# ============================================================================

def get_fw_version(repo_path: str = None) -> str:
    """
    Get firmware version string using git describe.
    
    Uses 'git describe --always --dirty' to get version info:
    - With tags: 'v1.2.3' or 'v1.2.3-5-gabcdef0'
    - Without tags: 'abcdef0' (short commit hash)
    - With uncommitted changes: adds '-dirty' suffix
    
    Args:
        repo_path: Path to git repository (uses cwd if None)
        
    Returns:
        Version string from git describe
        
    Raises:
        RuntimeError: If git command fails (git not installed or not a repo)
    """
    import subprocess
    
    cmd = ['git', 'describe', '--always', '--dirty']
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            cwd=repo_path
        )
        return result.stdout.strip()
        
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"git describe failed: {e.stderr.strip()}\n"
            f"Ensure you are in a git repository and git is installed."
        )
    except FileNotFoundError:
        raise RuntimeError(
            "git command not found. Please install git or disable "
            "FWCHECK_INCLUDE_FW_VERSION build flag."
        )


# ============================================================================
# ELF Symbol Extraction
# ============================================================================

def get_symbol_address(elf_path: str, symbol_name: str) -> int:
    """
    Extract symbol address from ELF file using arm-none-eabi-nm or nm.
    
    Args:
        elf_path: Path to ELF file
        symbol_name: Name of symbol to find
        
    Returns:
        Symbol address as integer
        
    Raises:
        ValueError: If symbol not found
    """
    import subprocess
    
    # Try arm-none-eabi-nm first, fall back to nm
    for nm_tool in ['arm-none-eabi-nm', 'nm']:
        try:
            result = subprocess.run(
                [nm_tool, elf_path],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2] == symbol_name:
                    return int(parts[0], 16)
                    
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    
    raise ValueError(f"Symbol '{symbol_name}' not found in {elf_path}")


def get_fwcheck_info_from_elf(elf_path: str) -> dict:
    """
    Extract firmware check section info from ELF file.
    
    Args:
        elf_path: Path to ELF file
        
    Returns:
        Dictionary with keys:
        - 'fw_start': Firmware start address
        - 'section_start': CRC section start address
        - 'section_end': CRC section end address
        - 'fw_size': Size of firmware to CRC (section_start - fw_start)
        - 'section_offset': Offset in binary file where CRC section starts
    """
    fw_start = get_symbol_address(elf_path, '__fwcheck_firmware_start')
    section_start = get_symbol_address(elf_path, '__fwcheck_section_start')
    section_end = get_symbol_address(elf_path, '__fwcheck_section_end')
    
    return {
        'fw_start': fw_start,
        'section_start': section_start,
        'section_end': section_end,
        'fw_size': section_start - fw_start,
        'section_offset': section_start - fw_start  # Offset in .bin file
    }


# ============================================================================
# ELF Patching Function
# ============================================================================

def patch_elf_file(elf_path: str, info: dict, crc_section: bytes, verbose: bool = True) -> bool:
    """
    Patch the ELF file with CRC data so debugger flashing works correctly.
    
    Directly modifies the ELF file by finding and updating the .fwcheck section.
    
    Args:
        elf_path: Path to firmware .elf file
        info: Section info dictionary from get_fwcheck_info_from_elf()
        crc_section: CRC section data (magic + CRC1 + CRC2 + optional git version)
        verbose: Print status messages
        
    Returns:
        True if successful, False otherwise
    """
    import subprocess
    import re
    
    try:
        # Get section info using readelf
        section_offset = None
        
        for tool in ['arm-none-eabi-readelf', 'readelf']:
            try:
                result = subprocess.run(
                    [tool, '-S', '-W', elf_path],  # -W for wide output
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Parse section headers to find .fwcheck
                # Format: [ Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
                # Example: [ 10] .fwcheck          PROGBITS        0800d1c4        00d1c4 00000c 00  WA  0   0  4
                for line in result.stdout.splitlines():
                    if '.fwcheck' in line:
                        # Use regex to extract offset (hex value after address)
                        # Pattern: .fwcheck followed by type, address, then offset
                        match = re.search(r'\.fwcheck\s+\w+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)', line)
                        if match:
                            section_offset = int(match.group(1), 16)
                            break
                        
                        # Alternative: split and find hex values
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == '.fwcheck' and i + 3 < len(parts):
                                # Type is at i+1, Address at i+2, Offset at i+3
                                try:
                                    section_offset = int(parts[i + 3], 16)
                                    break
                                except (ValueError, IndexError):
                                    continue
                        
                        if section_offset is not None:
                            break
                
                if section_offset is not None:
                    break
                    
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        
        if section_offset is None:
            if verbose:
                print(f"[FWCheck] WARNING: Could not find .fwcheck section offset in ELF")
            return False
        
        # Directly patch the ELF file at the section offset
        with open(elf_path, 'r+b') as f:
            f.seek(section_offset)
            f.write(crc_section)
        
        if verbose:
            print(f"[FWCheck] Successfully patched ELF file at offset 0x{section_offset:X}")
        
        return True
        
    except Exception as e:
        if verbose:
            print(f"[FWCheck] WARNING: Failed to patch ELF: {e}")
        return False


# ============================================================================
# Main CRC Injection Function
# ============================================================================

def inject_crc(bin_path: str, elf_path: str, use_hw_crc: bool = False, 
               verbose: bool = True, patch_elf: bool = True,
               fw_version_size: int = 0, repo_path: str = None) -> bool:
    """
    Calculate and inject CRC into firmware binary and optionally ELF file.
    
    Args:
        bin_path: Path to firmware .bin file
        elf_path: Path to firmware .elf file (for symbol extraction)
        use_hw_crc: Use hardware CRC polynomial if True
        verbose: Print status messages
        patch_elf: Also patch the ELF file for debugger flashing
        fw_version_size: Size of FW version field (0 = disabled)
        repo_path: Path to git repository for version extraction
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Calculate total section size
        section_size = FWCHECK_SECTION_SIZE
        if fw_version_size > 0:
            section_size += fw_version_size
        
        # Get section info from ELF
        info = get_fwcheck_info_from_elf(elf_path)
        
        if verbose:
            print(f"[FWCheck] Firmware start:    0x{info['fw_start']:08X}")
            print(f"[FWCheck] Section start:     0x{info['section_start']:08X}")
            print(f"[FWCheck] Section end:       0x{info['section_end']:08X}")
            print(f"[FWCheck] Firmware size:     {info['fw_size']} bytes")
            print(f"[FWCheck] Section size:      {section_size} bytes")
        
        # Read binary file
        with open(bin_path, 'rb') as f:
            bin_data = bytearray(f.read())
        
        # Ensure binary is large enough
        required_size = info['section_offset'] + section_size
        if len(bin_data) < required_size:
            # Extend binary with 0xFF (erased flash value)
            bin_data.extend(b'\xFF' * (required_size - len(bin_data)))
        
        # Extract firmware data (from start to CRC section)
        fw_data = bytes(bin_data[:info['section_offset']])
        
        # Pad to 4-byte boundary if needed
        padding_needed = (4 - (len(fw_data) % 4)) % 4
        if padding_needed:
            fw_data = fw_data + bytes(padding_needed)
            if verbose:
                print(f"[FWCheck] Padded {padding_needed} bytes for alignment")
        
        # Calculate CRC
        if use_hw_crc:
            crc_value = crc32_hw(fw_data)
            poly_name = "HW (0x04C11DB7)"
        else:
            crc_value = crc32_sw(fw_data)
            poly_name = "SW (0xEDB88320)"
        
        if verbose:
            print(f"[FWCheck] CRC polynomial:    {poly_name}")
            print(f"[FWCheck] Calculated CRC:    0x{crc_value:08X}")
        
        # Build CRC section: magic + CRC1 + CRC2
        crc_section = struct.pack('<III', FWCHECK_MAGIC, crc_value, crc_value)
        
        # Add FW version if enabled
        if fw_version_size > 0:
            fw_version = get_fw_version(repo_path)
            
            # Truncate with warning if too long (leave room for null terminator)
            max_len = fw_version_size - 1
            if len(fw_version) > max_len:
                if verbose:
                    print(f"[FWCheck] WARNING: FW version '{fw_version}' truncated to {max_len} chars")
                fw_version = fw_version[:max_len]
            
            # Encode and null-pad to exact size
            fw_bytes = fw_version.encode('utf-8')
            fw_bytes = fw_bytes + b'\x00' * (fw_version_size - len(fw_bytes))
            crc_section += fw_bytes
            
            if verbose:
                print(f"[FWCheck] FW version:        '{fw_version}'")
        
        # Inject into binary
        offset = info['section_offset']
        bin_data[offset:offset + section_size] = crc_section
        
        # Write modified binary
        with open(bin_path, 'wb') as f:
            f.write(bin_data)
        
        if verbose:
            print(f"[FWCheck] Magic: 0x{FWCHECK_MAGIC:08X} ('FWCH')")
            print(f"[FWCheck] Successfully patched BIN file at offset 0x{offset:X}")
        
        # Also patch the ELF file for debugger flashing
        if patch_elf:
            elf_patched = patch_elf_file(elf_path, info, crc_section, verbose)
            if not elf_patched and verbose:
                print(f"[FWCheck] WARNING: Could not patch ELF file")
        
        return True
        
    except Exception as e:
        print(f"[FWCheck] ERROR: {e}", file=sys.stderr)
        return False


# ============================================================================
# PlatformIO Integration
# ============================================================================

def is_define_set(env, define_name: str) -> bool:
    """
    Check if a preprocessor define is set in the build environment.
    
    Args:
        env: PlatformIO environment
        define_name: Name of the define to check
        
    Returns:
        True if define is set, False otherwise
    """
    # Check BUILD_FLAGS
    build_flags = env.get("BUILD_FLAGS", [])
    for flag in build_flags:
        flag_str = str(flag)
        # Match -DDEFINE or -DDEFINE=value
        if f'-D{define_name}' in flag_str or f'-D {define_name}' in flag_str:
            return True
    
    # Check CPPDEFINES
    cppdefines = env.get("CPPDEFINES", [])
    for define in cppdefines:
        if isinstance(define, tuple):
            if define[0] == define_name:
                return True
        elif define == define_name:
            return True
    
    return False


def get_define_value(env, define_name: str, default=None):
    """
    Get the value of a preprocessor define from the build environment.
    
    Args:
        env: PlatformIO environment
        define_name: Name of the define to get value for
        default: Default value if define not found or has no value
        
    Returns:
        The define's value as string, or default if not found/no value
    """
    import re
    
    # Check BUILD_FLAGS for -DNAME=VALUE
    build_flags = env.get("BUILD_FLAGS", [])
    for flag in build_flags:
        flag_str = str(flag)
        # Match -DDEFINE=value
        match = re.search(rf'-D\s*{re.escape(define_name)}=([^\s]+)', flag_str)
        if match:
            return match.group(1)
    
    # Check CPPDEFINES (tuple format: (name, value))
    cppdefines = env.get("CPPDEFINES", [])
    for define in cppdefines:
        if isinstance(define, tuple) and len(define) >= 2:
            if define[0] == define_name:
                return str(define[1])
    
    return default


def post_build_action(source, target, env):
    """
    PlatformIO post-build action callback.
    Called after firmware is built to inject CRC.
    """
    # Check if FWCHECK_ENABLED is defined - skip if not
    if not is_define_set(env, 'FWCHECK_ENABLED'):
        print(f"\n[FWCheck] FWCHECK_ENABLED not defined, skipping CRC injection\n")
        return
    
    # Get paths
    build_dir = env.subst("$BUILD_DIR")
    prog_name = env.subst("$PROGNAME")
    project_dir = env.subst("$PROJECT_DIR")
    
    bin_path = os.path.join(build_dir, f"{prog_name}.bin")
    elf_path = os.path.join(build_dir, f"{prog_name}.elf")
    
    # Check if hardware CRC is enabled
    use_hw_crc = is_define_set(env, 'FWCHECK_USE_HW_CRC')
    
    # Check if FW version is enabled
    fw_version_size = 0
    if is_define_set(env, 'FWCHECK_INCLUDE_FW_VERSION'):
        # Get custom size or use default
        size_str = get_define_value(env, 'FWCHECK_FW_VERSION_SIZE')
        if size_str:
            try:
                fw_version_size = int(size_str)
            except ValueError:
                print(f"[FWCheck] WARNING: Invalid FWCHECK_FW_VERSION_SIZE '{size_str}', using default")
                fw_version_size = FWCHECK_FW_VERSION_SIZE_DEFAULT
        else:
            fw_version_size = FWCHECK_FW_VERSION_SIZE_DEFAULT
    
    print(f"\n{'='*60}")
    print("libFWCheck: Injecting firmware CRC")
    if fw_version_size > 0:
        print(f"            FW version enabled ({fw_version_size} bytes)")
    print('='*60)
    
    success = inject_crc(
        bin_path, elf_path, use_hw_crc, 
        verbose=True, patch_elf=True,
        fw_version_size=fw_version_size,
        repo_path=project_dir
    )
    
    print('='*60 + '\n')
    
    if not success:
        env.Exit(1)


# Register with PlatformIO
if PLATFORMIO_ENV:
    env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", post_build_action)


# ============================================================================
# Standalone CLI
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Inject CRC into firmware binary and optionally ELF file'
    )
    parser.add_argument('bin_file', help='Path to firmware .bin file')
    parser.add_argument('elf_file', help='Path to firmware .elf file')
    parser.add_argument('--hw-crc', action='store_true',
                        help='Use hardware CRC polynomial (0x04C11DB7)')
    parser.add_argument('--no-patch-elf', action='store_true',
                        help='Do not patch the ELF file')
    parser.add_argument('--fw-version', action='store_true',
                        help='Include firmware version string (from git describe)')
    parser.add_argument('--fw-version-size', type=int, 
                        default=FWCHECK_FW_VERSION_SIZE_DEFAULT,
                        help=f'Size of FW version field (default: {FWCHECK_FW_VERSION_SIZE_DEFAULT})')
    parser.add_argument('--repo-path', type=str, default=None,
                        help='Path to git repository (default: current directory)')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress output')
    
    args = parser.parse_args()
    
    # Determine FW version size (0 if disabled)
    fw_version_size = args.fw_version_size if args.fw_version else 0
    
    success = inject_crc(
        args.bin_file,
        args.elf_file,
        use_hw_crc=args.hw_crc,
        verbose=not args.quiet,
        patch_elf=not args.no_patch_elf,
        fw_version_size=fw_version_size,
        repo_path=args.repo_path
    )
    
    sys.exit(0 if success else 1)
