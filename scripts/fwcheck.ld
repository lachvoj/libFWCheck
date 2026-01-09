/**
 * @file fwcheck.ld
 * @brief Linker script fragment for firmware CRC verification
 * 
 * This file should be included in your main linker script using:
 *   INCLUDE "fwcheck.ld"
 * 
 * Or used as an overlay with PlatformIO's board_build.ldscript setting.
 * 
 * Provides:
 * - .fwcheck section placed immediately after firmware content
 * - 4-byte alignment for hardware CRC compatibility
 * - Exported symbols for runtime access:
 *   - __fwcheck_firmware_start: Start of firmware (flash base)
 *   - __fwcheck_section_start: Start of CRC storage section
 *   - __fwcheck_section_end: End of CRC storage section
 */

/* 
 * IMPORTANT: This is a linker script FRAGMENT meant to be included
 * in the main linker script. For standalone use with PlatformIO,
 * see fwcheck_stm32f103.ld which is a complete linker script.
 */

SECTIONS
{
    /*
     * Firmware CRC storage section
     * 
     * Placed after all other flash content (.text, .rodata, .data init)
     * Structure: [4-byte magic][4-byte CRC1][4-byte CRC2] = 12 bytes
     * 
     * The KEEP() ensures this section is not garbage collected by LTO.
     * The actual content comes from FWCheck.c placeholder struct which
     * creates a PROGBITS section that the post-build script can patch.
     */
    .fwcheck : ALIGN(4)
    {
        /* Export symbol for runtime - start of CRC section */
        __fwcheck_section_start = .;
        
        /* Include CRC storage placeholder from FWCheck.c */
        KEEP(*(.fwcheck))
        KEEP(*(.fwcheck.*))
        
        . = ALIGN(4);
        /* Export symbol for runtime - end of CRC section */
        __fwcheck_section_end = .;
    } > FLASH
}

/* 
 * Export firmware start address 
 * This should match FLASH origin in your memory map (typically 0x08000000 for STM32)
 */
__fwcheck_firmware_start = ORIGIN(FLASH);
