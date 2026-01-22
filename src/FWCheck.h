/**
 * @file FWCheck.h
 * @brief Firmware CRC verification library public API
 * 
 * This library provides firmware integrity verification using CRC32 with:
 * - Hardware CRC acceleration (STM32) when FWCHECK_USE_HW_CRC is defined
 * - Software CRC32 fallback for other platforms
 * - Dual-copy CRC storage with 3-way majority voting
 * - Magic number validation for stored CRC detection
 * 
 * Usage:
 * 1. Include linker script fragment (fwcheck.ld) in your build
 * 2. Add post-build script (fwcheck.py) to inject CRC after compilation
 * 3. Call FWCheck_Verify() at runtime to validate firmware integrity
 */

#ifndef FWCHECK_H
#define FWCHECK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/*******************************************************************************
 * Configuration
 ******************************************************************************/

/**
 * @def FWCHECK_USE_HW_CRC
 * @brief Define this to use STM32 hardware CRC peripheral
 * 
 * When defined:
 *   - Uses STM32 HAL CRC with polynomial 0x04C11DB7
 *   - Requires HAL_CRC_MODULE_ENABLED in stm32f1xx_hal_conf.h
 *   - Python script must use matching polynomial
 * 
 * When not defined:
 *   - Uses software CRC32 with standard polynomial 0xEDB88320
 *   - Portable across all platforms
 */

/**
 * @def FWCHECK_MAGIC
 * @brief Magic number to identify valid CRC storage section
 * "FWCH" in little-endian = 0x48435746
 */
#define FWCHECK_MAGIC           0x48435746UL

/**
 * @def FWCHECK_SECTION_SIZE
 * @brief Size of CRC storage section in bytes (base size without FW version)
 * Layout: [4-byte magic][4-byte CRC1][4-byte CRC2] = 12 bytes
 */
#define FWCHECK_SECTION_SIZE    12

/**
 * @def FWCHECK_INCLUDE_FW_VERSION
 * @brief Define this to include firmware version string (from git describe)
 * 
 * When defined:
 *   - Adds szFwVersion field to FWCheck_Storage_t structure
 *   - Post-build script injects git describe --always --dirty output
 *   - FWCheck_GetFwVersion() returns the stored version string
 * 
 * When not defined:
 *   - No version string stored
 *   - FWCheck_GetFwVersion() returns NULL
 */

/**
 * @def FWCHECK_FW_VERSION_SIZE
 * @brief Size of firmware version string buffer (including null terminator)
 * Default: 32 bytes (sufficient for "v1.2.3-99-gabcdef12-dirty")
 * Can be overridden via build flags: -DFWCHECK_FW_VERSION_SIZE=48
 */
#ifdef FWCHECK_INCLUDE_FW_VERSION
    #ifndef FWCHECK_FW_VERSION_SIZE
        #define FWCHECK_FW_VERSION_SIZE    32
    #endif
#endif

/*******************************************************************************
 * Result Codes
 ******************************************************************************/

/**
 * @enum FWCheck_Result_t
 * @brief Result codes for firmware verification operations
 */
typedef enum {
    /** Firmware CRC verified successfully (2+ of 3 votes match) */
    FWCHECK_OK = 0,
    
    /** CRC mismatch - no majority agreement between calculated and stored CRCs */
    FWCHECK_CRC_MISMATCH = 1,
    
    /** No valid CRC stored - magic number not found or invalid */
    FWCHECK_NO_CRC_STORED = 2,
    
    /** Internal error during CRC calculation */
    FWCHECK_ERROR = 3
} FWCheck_Result_t;

/*******************************************************************************
 * CRC Storage Structure
 ******************************************************************************/

/**
 * @struct FWCheck_Storage_t
 * @brief Structure of the CRC storage section in flash
 * 
 * This structure is placed at the end of firmware by the linker script
 * and populated by the post-build Python script.
 * 
 * When FWCHECK_INCLUDE_FW_VERSION is defined, an additional field
 * acFwVersion[FWCHECK_FW_VERSION_SIZE] is appended after the CRC copies.
 */
typedef struct __attribute__((packed)) {
    uint32_t u32Magic;      /**< Magic number (FWCHECK_MAGIC) for validation */
    uint32_t u32CrcCopy1;   /**< Primary CRC32 copy */
    uint32_t u32CrcCopy2;   /**< Secondary CRC32 copy (backup) */
#ifdef FWCHECK_INCLUDE_FW_VERSION
    char acFwVersion[FWCHECK_FW_VERSION_SIZE]; /**< Firmware version (null-padded by build script) */
#endif
} FWCheck_Storage_t;

/*******************************************************************************
 * Public API
 ******************************************************************************/

/**
 * @brief Verify firmware integrity using 3-way majority voting
 * 
 * Performs the following:
 * 1. Validates magic number in CRC storage section
 * 2. Calculates CRC32 over firmware flash content
 * 3. Compares calculated CRC with both stored copies
 * 4. Returns OK if at least 2 of 3 values match
 * 
 * Voting logic:
 * - If calculated == copy1 == copy2: FWCHECK_OK
 * - If calculated == copy1 != copy2: FWCHECK_OK (copy2 corrupted)
 * - If calculated == copy2 != copy1: FWCHECK_OK (copy1 corrupted)
 * - If copy1 == copy2 != calculated: FWCHECK_CRC_MISMATCH (firmware corrupted)
 * - If all three differ: FWCHECK_CRC_MISMATCH
 * 
 * @return FWCheck_Result_t verification result
 */
FWCheck_Result_t FWCheck_Verify(void);

/**
 * @brief Calculate CRC32 of current firmware in flash
 * 
 * Calculates CRC32 from firmware start address to the CRC storage section.
 * Uses hardware CRC if FWCHECK_USE_HW_CRC is defined, otherwise software.
 * 
 * @return uint32_t calculated CRC32 value
 */
uint32_t FWCheck_GetFwCRC(void);

/**
 * @brief Get both stored CRC copies from flash
 * 
 * Reads the CRC values stored in the .fwcheck section.
 * Does not validate magic - use FWCheck_Verify() for full validation.
 * 
 * @param[out] pu32Copy1 Pointer to store first CRC copy (NULL to skip)
 * @param[out] pu32Copy2 Pointer to store second CRC copy (NULL to skip)
 * @return true if magic is valid and values were read
 * @return false if magic is invalid (CRC section not initialized)
 */
bool FWCheck_GetStoredCRC(uint32_t* pu32Copy1, uint32_t* pu32Copy2);

/**
 * @brief Get the magic number from CRC storage section
 * 
 * Useful for diagnostics to check if CRC section is properly initialized.
 * 
 * @return uint32_t magic value (should be FWCHECK_MAGIC if valid)
 */
uint32_t FWCheck_GetMagic(void);

/**
 * @brief Get firmware size used for CRC calculation
 * 
 * Returns the size of firmware from start to CRC section as defined by linker.
 * 
 * @return uint32_t firmware size in bytes
 */
uint32_t FWCheck_GetFwSize(void);

/**
 * @brief Initialize hardware CRC peripheral (if using hardware CRC)
 * 
 * Must be called before FWCheck_Verify() or FWCheck_GetFwCRC() when
 * FWCHECK_USE_HW_CRC is defined. No-op for software CRC builds.
 * 
 * @return true if initialization successful
 * @return false if initialization failed
 */
bool FWCheck_Init(void);

/**
 * @brief Get firmware version string stored in flash
 * 
 * Returns the version string (from git describe) injected during build.
 * Only available when FWCHECK_INCLUDE_FW_VERSION is defined.
 * 
 * @return const char* pointer to null-terminated version string,
 *         or NULL if feature disabled or magic invalid
 */
const char* FWCheck_GetFwVersion(void);

#ifdef __cplusplus
}
#endif

#endif /* FWCHECK_H */
