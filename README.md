# libFWCheck - Firmware CRC Verification Library

A lightweight library for embedded firmware integrity verification using CRC32 with hardware acceleration support and dual-copy voting for reliability.

## Features

- **Hardware CRC Acceleration**: Uses STM32 CRC peripheral when available (polynomial `0x04C11DB7`)
- **Software CRC Fallback**: Portable CRC32 implementation (polynomial `0xEDB88320`) for other platforms
- **3-Way Majority Voting**: Compares calculated CRC against two stored copies for reliability
- **Magic Number Validation**: Detects if CRC section is properly initialized
- **Minimal Flash Overhead**: Only 12 bytes for CRC storage section
- **Post-Build Integration**: Automatic CRC injection via PlatformIO script
- **Linker Script Support**: Places CRC section immediately after firmware content

## Quick Start

### 1. Add Library to Project

In your `platformio.ini`, add the library dependency:

```ini
lib_deps = 
    libFWCheck
```

Or symlink to your lib folder:
```bash
ln -s /path/to/libFWCheck lib/libFWCheck
```

### 2. Configure Build

Add to your `platformio.ini`:

```ini
[env:your_board]
platform = ststm32
board = bluepill_f103c8
framework = arduino

# Use the custom linker script with CRC section
board_build.ldscript = lib/libFWCheck/scripts/fwcheck_stm32f103c8.ld

# Add post-build CRC injection script
extra_scripts = 
    post:lib/libFWCheck/scripts/fwcheck.py

# Optional: Enable hardware CRC (STM32 only)
build_flags = 
    -DFWCHECK_USE_HW_CRC
```

### 3. Use in Your Code

```c
#include "FWCheck.h"

void setup() {
    // Initialize (required for hardware CRC)
    FWCheck_Init();
    
    // Verify firmware integrity
    FWCheck_Result_t result = FWCheck_Verify();
    
    switch (result) {
        case FWCHECK_OK:
            // Firmware is valid
            break;
            
        case FWCHECK_CRC_MISMATCH:
            // Firmware corrupted - handle error
            break;
            
        case FWCHECK_NO_CRC_STORED:
            // No CRC in firmware (first boot or CRC injection failed)
            break;
            
        case FWCHECK_ERROR:
            // Internal error during verification
            break;
    }
}
```

## API Reference

### Functions

#### `bool FWCheck_Init(void)`
Initialize the CRC module. Required before using other functions when hardware CRC is enabled.
- **Returns**: `true` on success, `false` on failure

#### `FWCheck_Result_t FWCheck_Verify(void)`
Perform full firmware verification with 3-way voting.
- **Returns**: Result code indicating verification status

#### `uint32_t FWCheck_GetFwCRC(void)`
Calculate CRC32 of current firmware content.
- **Returns**: Calculated CRC32 value

#### `bool FWCheck_GetStoredCRC(uint32_t* copy1, uint32_t* copy2)`
Retrieve both stored CRC copies.
- **Parameters**: Pointers to store CRC values (NULL to skip)
- **Returns**: `true` if magic is valid, `false` otherwise

#### `uint32_t FWCheck_GetMagic(void)`
Get the magic number from CRC storage section.
- **Returns**: Magic value (should be `0x48435746` if valid)

#### `uint32_t FWCheck_GetFwSize(void)`
Get firmware size used for CRC calculation.
- **Returns**: Firmware size in bytes (from start to CRC section)

#### `const char* FWCheck_GetFwVersion(void)`
Get firmware version string stored in flash (from git describe).
- **Returns**: Pointer to null-terminated version string, or `NULL` if feature disabled or magic invalid
- **Note**: Only available when `FWCHECK_INCLUDE_FW_VERSION` is defined

### Result Codes

| Code | Value | Description |
|------|-------|-------------|
| `FWCHECK_OK` | 0 | Firmware verified (2+ of 3 votes match) |
| `FWCHECK_CRC_MISMATCH` | 1 | CRC mismatch (firmware corrupted) |
| `FWCHECK_NO_CRC_STORED` | 2 | No valid CRC stored (magic invalid) |
| `FWCHECK_ERROR` | 3 | Internal error |

## 3-Way Voting Logic

The verification uses majority voting between three values:
1. **Calculated CRC**: Computed from current flash content
2. **Stored Copy 1**: Primary CRC in .fwcheck section
3. **Stored Copy 2**: Backup CRC in .fwcheck section

| Calculated | Copy 1 | Copy 2 | Result |
|------------|--------|--------|--------|
| A | A | A | `FWCHECK_OK` |
| A | A | B | `FWCHECK_OK` (Copy 2 corrupted) |
| A | B | A | `FWCHECK_OK` (Copy 1 corrupted) |
| A | B | B | `FWCHECK_CRC_MISMATCH` (Firmware changed) |
| A | B | C | `FWCHECK_CRC_MISMATCH` (Multiple corruption) |

## CRC Storage Section Layout

The `.fwcheck` section is 12 bytes (base) placed immediately after firmware content:

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | Magic number (`0x48435746` = "FWCH") |
| 0x04 | 4 | CRC32 Copy 1 (primary) |
| 0x08 | 4 | CRC32 Copy 2 (backup) |
| 0x0C | N | Firmware version string (optional, only if `FWCHECK_INCLUDE_FW_VERSION` defined) |

**Note**: When firmware version is enabled, section size becomes 12 + `FWCHECK_FW_VERSION_SIZE` bytes (default 44 bytes total).

## Firmware Version Feature

The library can optionally store the firmware version (from `git describe`) in flash alongside the CRC. This allows runtime identification of firmware builds.

### Enabling Version Storage

Add to your `platformio.ini` build_flags:

```ini
build_flags = 
    -DFWCHECK_INCLUDE_FW_VERSION
    ; Optional: customize version string buffer size (default 32)
    -DFWCHECK_FW_VERSION_SIZE=48
```

### Version String Format

The version string is generated by `git describe --always --dirty`:

| Git State | Example Output |
|-----------|----------------|
| Tagged commit | `v1.2.3` |
| After tag (5 commits) | `v1.2.3-5-gabcdef0` |
| No tags | `abcdef0` |
| Uncommitted changes | `v1.2.3-dirty` |

### Usage Example

```c
#include "FWCheck.h"

void printFirmwareInfo() {
    const char* version = FWCheck_GetFwVersion();
    
    if (version != NULL) {
        Serial.printf("Firmware version: %s\n", version);
    } else {
        Serial.println("Version info not available");
    }
}
```

## Build Configuration

### Hardware vs Software CRC

| Mode | Define | Polynomial | Use Case |
|------|--------|------------|----------|
| Hardware | `FWCHECK_USE_HW_CRC` | `0x04C11DB7` | STM32 with CRC peripheral |
| Software | (default) | `0xEDB88320` | All platforms |

**Important**: The Python script automatically detects `FWCHECK_USE_HW_CRC` from build flags and uses the matching polynomial.

### Build Flags Summary

| Flag | Description | Default |
|------|-------------|---------|
| `FWCHECK_USE_HW_CRC` | Use STM32 hardware CRC peripheral | Disabled (software CRC) |
| `FWCHECK_INCLUDE_FW_VERSION` | Store git version string in flash | Disabled |
| `FWCHECK_FW_VERSION_SIZE=N` | Version string buffer size (bytes) | 32 |

### STM32 HAL Configuration

When using hardware CRC, ensure your `stm32f1xx_hal_conf.h` includes:

```c
#define HAL_CRC_MODULE_ENABLED
```

## File Structure

```
libFWCheck/
├── library.json              # PlatformIO metadata
├── README.md                 # This file
├── src/
│   ├── FWCheck.h             # Public API header
│   ├── FWCheck.c             # Core implementation
│   └── FWCheck_HW_STM32.c    # STM32 hardware CRC
└── scripts/
    ├── fwcheck.py            # Post-build CRC injection
    ├── fwcheck.ld            # Linker fragment (for inclusion)
    └── fwcheck_stm32f103c8.ld # Complete STM32F103C8 linker script
```

## Linker Script Options

### Option 1: Use Complete Linker Script (Recommended)

For STM32F103C8 (64KB Flash, 20KB RAM):
```ini
board_build.ldscript = lib/libFWCheck/scripts/fwcheck_stm32f103c8.ld
```

### Option 2: Include Fragment in Custom Script

Add to your linker script after `.data` section:
```ld
INCLUDE "lib/libFWCheck/scripts/fwcheck.ld"
```

## Standalone Script Usage

The `fwcheck.py` script can be used standalone:

```bash
# Software CRC (default)
python fwcheck.py firmware.bin firmware.elf

# Hardware CRC polynomial
python fwcheck.py firmware.bin firmware.elf --hw-crc

# Quiet mode
python fwcheck.py firmware.bin firmware.elf -q
```

## Example: Complete Integration

### platformio.ini

```ini
[env:bluepill_f103c8_with_crc]
platform = ststm32
board = bluepill_f103c8
framework = arduino

; Linker script with CRC section
board_build.ldscript = lib/libFWCheck/scripts/fwcheck_stm32f103c8.ld

; Post-build CRC injection
extra_scripts = 
    post:lib/libFWCheck/scripts/fwcheck.py

; Enable hardware CRC and firmware version
build_flags = 
    -DFWCHECK_USE_HW_CRC
    -DHAL_CRC_MODULE_ENABLED
    -DFWCHECK_INCLUDE_FW_VERSION

lib_deps = 
    libFWCheck
```

### main.cpp

```cpp
#include <Arduino.h>
#include "FWCheck.h"

void setup() {
    Serial.begin(115200);
    
    // Initialize CRC module
    if (!FWCheck_Init()) {
        Serial.println("FWCheck init failed!");
        while(1);
    }
    
    // Verify firmware
    Serial.print("Verifying firmware... ");
    FWCheck_Result_t result = FWCheck_Verify();
    
    if (result == FWCHECK_OK) {
        Serial.println("OK");
        
        // Display firmware version (if enabled)
        const char* version = FWCheck_GetFwVersion();
        if (version != NULL) {
            Serial.printf("Firmware version: %s\n", version);
        }
        
        // Optional: Display CRC values
        uint32_t crc1, crc2;
        FWCheck_GetStoredCRC(&crc1, &crc2);
        Serial.printf("Stored CRC: 0x%08X / 0x%08X\n", crc1, crc2);
        Serial.printf("Calculated: 0x%08X\n", FWCheck_GetFwCRC());
        Serial.printf("Firmware size: %lu bytes\n", FWCheck_GetFwSize());
    } else {
        Serial.printf("FAILED (code %d)\n", result);
        // Handle failure according to your requirements
    }
}

void loop() {
    // Your application code
}
```

## Build Output

During build, you'll see CRC injection output:

```
============================================================
libFWCheck: Injecting firmware CRC
============================================================
[FWCheck] Firmware start:    0x08000000
[FWCheck] CRC section start: 0x0800A1B4
[FWCheck] CRC section end:   0x0800A1D4
[FWCheck] Firmware size:     41396 bytes
[FWCheck] CRC polynomial:    HW (0x04C11DB7)
[FWCheck] Calculated CRC:    0x3A7B9C21
[FWCheck] FW version:        v1.2.3-5-gabcdef0
[FWCheck] Injected CRC at offset 0x0000A1B4
[FWCheck] Magic: 0x48435746 ('FWCH')
[FWCheck] Successfully updated firmware.bin
============================================================
```

**Note**: The `FW version` line only appears when `FWCHECK_INCLUDE_FW_VERSION` is defined.

## Troubleshooting

### "Symbol not found" Error
Ensure you're using the correct linker script that defines:
- `__fwcheck_firmware_start`
- `__fwcheck_section_start`
- `__fwcheck_section_end`

### CRC Mismatch on First Boot
- Verify post-build script is running (check build output)
- Ensure `.bin` file is being flashed (not `.hex`)
- Check linker script is being used

### Hardware CRC Init Failed
- Verify `HAL_CRC_MODULE_ENABLED` is defined
- Check CRC peripheral clock is enabled

### Version String is NULL
- Ensure `FWCHECK_INCLUDE_FW_VERSION` is defined in build flags
- Verify the build is running from a git repository
- Check that `git` is installed and accessible during build
- Confirm CRC section magic is valid (`FWCheck_GetMagic() == 0x48435746`)

### Version String Truncated
- Increase `FWCHECK_FW_VERSION_SIZE` in build flags (default is 32 bytes)
- Example: `-DFWCHECK_FW_VERSION_SIZE=48`

## License

MIT License - See LICENSE file for details.
