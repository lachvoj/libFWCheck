/**
 * @file FWCheck.c
 * @brief Firmware CRC verification implementation
 * 
 * Contains:
 * - 3-way majority voting logic
 * - Software CRC32 implementation (when FWCHECK_USE_HW_CRC not defined)
 * - Flash memory access for CRC calculation
 */

#include "FWCheck.h"
#include <string.h>

/*******************************************************************************
 * CRC Storage Placeholder
 * 
 * This creates actual content in the .fwcheck section so the linker
 * creates a PROGBITS section (not NOBITS). The post-build script will
 * overwrite this with the actual CRC values.
 ******************************************************************************/

/** Placeholder CRC storage - will be overwritten by post-build script */
__attribute__((section(".fwcheck"), used))
static const FWCheck_Storage_t _sFWCheckPlaceholder = {
    .u32Magic = 0xFFFFFFFF,     /* Will be replaced with FWCHECK_MAGIC */
    .u32CrcCopy1 = 0xFFFFFFFF,  /* Will be replaced with calculated CRC */
    .u32CrcCopy2 = 0xFFFFFFFF   /* Will be replaced with calculated CRC */
};

/*******************************************************************************
 * Linker-provided symbols
 * These are defined in fwcheck.ld and represent addresses, not values
 ******************************************************************************/

/** Start of firmware (typically 0x08000000 for STM32) */
extern uint32_t __fwcheck_firmware_start;

/** Start of CRC storage section (end of firmware content) */
extern uint32_t __fwcheck_section_start;

/** End of CRC storage section */
extern uint32_t __fwcheck_section_end;

/*******************************************************************************
 * Private macros
 ******************************************************************************/

/** Get address value from linker symbol */
#define FWCHECK_FW_START_ADDR       ((uint32_t)&__fwcheck_firmware_start)
#define FWCHECK_SECTION_START_ADDR  ((uint32_t)&__fwcheck_section_start)
#define FWCHECK_SECTION_END_ADDR    ((uint32_t)&__fwcheck_section_end)

/** Pointer to CRC storage structure in flash */
#define FWCHECK_STORAGE_PTR         ((const FWCheck_Storage_t*)FWCHECK_SECTION_START_ADDR)

/** Firmware size (from start to CRC section) */
#define FWCHECK_FW_SIZE             (FWCHECK_SECTION_START_ADDR - FWCHECK_FW_START_ADDR)

/*******************************************************************************
 * CRC32 Implementation Selection
 ******************************************************************************/

#ifdef FWCHECK_USE_HW_CRC
    /* Hardware CRC - implementation in FWCheck_HW_STM32.c */
    extern uint32_t FWCheck_HW_Calculate(const uint8_t* pu8Data, uint32_t u32Length);
    extern bool FWCheck_HW_Init(void);
    
    #define FWCHECK_CRC_CALCULATE(data, len)    FWCheck_HW_Calculate((data), (len))
    #define FWCHECK_CRC_INIT()                  FWCheck_HW_Init()
#else
    /* Software CRC32 - standard polynomial 0xEDB88320 (bit-reversed 0x04C11DB7) */
    
    /**
     * @brief Calculate CRC32 using software implementation
     * @param pu8Data Pointer to data buffer
     * @param u32Length Data length in bytes
     * @return uint32_t CRC32 value
     */
    static uint32_t FWCheck_SW_Calculate(const uint8_t* pu8Data, uint32_t u32Length)
    {
        uint32_t u32Crc = 0xFFFFFFFFUL;
        
        while (u32Length--)
        {
            u32Crc ^= *pu8Data++;
            
            for (uint8_t u8Bit = 0; u8Bit < 8; u8Bit++)
            {
                if (u32Crc & 1)
                {
                    u32Crc = (u32Crc >> 1) ^ 0xEDB88320UL;
                }
                else
                {
                    u32Crc >>= 1;
                }
            }
        }
        
        return ~u32Crc;
    }
    
    #define FWCHECK_CRC_CALCULATE(data, len)    FWCheck_SW_Calculate((data), (len))
    #define FWCHECK_CRC_INIT()                  (true)
#endif

/*******************************************************************************
 * Public Functions
 ******************************************************************************/

bool FWCheck_Init(void)
{
    return FWCHECK_CRC_INIT();
}

uint32_t FWCheck_GetMagic(void)
{
    return FWCHECK_STORAGE_PTR->u32Magic;
}

uint32_t FWCheck_GetFwSize(void)
{
    return FWCHECK_FW_SIZE;
}

bool FWCheck_GetStoredCRC(uint32_t* pu32Copy1, uint32_t* pu32Copy2)
{
    /* Check magic first */
    if (FWCHECK_STORAGE_PTR->u32Magic != FWCHECK_MAGIC)
    {
        return false;
    }
    
    /* Return requested values */
    if (pu32Copy1 != NULL)
    {
        *pu32Copy1 = FWCHECK_STORAGE_PTR->u32CrcCopy1;
    }
    
    if (pu32Copy2 != NULL)
    {
        *pu32Copy2 = FWCHECK_STORAGE_PTR->u32CrcCopy2;
    }
    
    return true;
}

uint32_t FWCheck_GetFwCRC(void)
{
    const uint8_t* pu8FwStart = (const uint8_t*)FWCHECK_FW_START_ADDR;
    uint32_t u32FwSize = FWCHECK_FW_SIZE;
    
    return FWCHECK_CRC_CALCULATE(pu8FwStart, u32FwSize);
}

FWCheck_Result_t FWCheck_Verify(void)
{
    uint32_t u32StoredCrc1;
    uint32_t u32StoredCrc2;
    uint32_t u32CalculatedCrc;
    uint8_t u8Votes;
    
    /* Step 1: Validate magic number */
    if (FWCHECK_STORAGE_PTR->u32Magic != FWCHECK_MAGIC)
    {
        return FWCHECK_NO_CRC_STORED;
    }
    
    /* Step 2: Read stored CRC copies */
    u32StoredCrc1 = FWCHECK_STORAGE_PTR->u32CrcCopy1;
    u32StoredCrc2 = FWCHECK_STORAGE_PTR->u32CrcCopy2;
    
    /* Step 3: Calculate CRC over firmware */
    u32CalculatedCrc = FWCheck_GetFwCRC();
    
    /* Step 4: 3-way majority voting
     * 
     * We have 3 values:
     * - u32CalculatedCrc (from flash content)
     * - u32StoredCrc1 (primary copy)
     * - u32StoredCrc2 (backup copy)
     * 
     * Need at least 2 matching values for FWCHECK_OK
     */
    u8Votes = 0;
    
    /* Check if calculated matches copy1 */
    if (u32CalculatedCrc == u32StoredCrc1)
    {
        u8Votes++;
    }
    
    /* Check if calculated matches copy2 */
    if (u32CalculatedCrc == u32StoredCrc2)
    {
        u8Votes++;
    }
    
    /* Check if both stored copies match (regardless of calculated) */
    if (u32StoredCrc1 == u32StoredCrc2)
    {
        u8Votes++;
    }
    
    /* Voting decision:
     * - votes = 3: All match -> OK
     * - votes = 2: Two match -> OK (one value corrupted but majority agrees)
     *   - calc == copy1 == copy2: all match (votes=3)
     *   - calc == copy1 != copy2: calc and copy1 agree (votes=1), but copy1==copy2 check fails
     *     Actually need to reconsider: if calc==copy1 and copy1!=copy2, votes=1
     *     But we want OK if calc matches either copy...
     * 
     * Let's reconsider the logic:
     * - If calculated matches BOTH stored: definitely OK (all 3 agree)
     * - If calculated matches ONE stored: OK (2 of 3 agree - calc + one copy)
     * - If calculated matches NEITHER but copies match each other: MISMATCH (firmware changed)
     * - If all three differ: MISMATCH
     */
    
    /* Simplified correct logic */
    if (u32CalculatedCrc == u32StoredCrc1 || u32CalculatedCrc == u32StoredCrc2)
    {
        /* Calculated matches at least one stored copy = 2+ agreement */
        return FWCHECK_OK;
    }
    
    if (u32StoredCrc1 == u32StoredCrc2)
    {
        /* Both stored copies agree but calculated differs = firmware corrupted */
        return FWCHECK_CRC_MISMATCH;
    }
    
    /* All three values differ = cannot determine correct value */
    return FWCHECK_CRC_MISMATCH;
}
