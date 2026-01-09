/**
 * @file FWCheck_HW_STM32.c
 * @brief STM32 Hardware CRC implementation for firmware verification
 * 
 * This file is only compiled when FWCHECK_USE_HW_CRC is defined.
 * Uses STM32 HAL CRC peripheral with fixed polynomial 0x04C11DB7.
 * 
 * Requirements:
 * - HAL_CRC_MODULE_ENABLED must be defined in stm32f1xx_hal_conf.h
 * - Matching polynomial must be used in post-build script
 */

#ifdef FWCHECK_USE_HW_CRC

#include "FWCheck.h"

/* STM32 LL includes - smaller code size than HAL (all functions are __STATIC_INLINE) */
#if defined(STM32F1xx) || defined(STM32F103xB) || defined(STM32F103x8)
    #include "stm32f1xx_ll_bus.h"
    #include "stm32f1xx_ll_crc.h"
#elif defined(STM32F4xx)
    #include "stm32f4xx_ll_bus.h"
    #include "stm32f4xx_ll_crc.h"
#else
    #error "Unsupported STM32 family for hardware CRC. Define appropriate STM32 family or disable FWCHECK_USE_HW_CRC"
#endif

/*******************************************************************************
 * Private Variables
 ******************************************************************************/

/** Initialization flag */
static bool bInitialized = false;

/*******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Initialize STM32 hardware CRC peripheral
 * @return true if initialization successful
 * @return false if initialization failed
 */
bool FWCheck_HW_Init(void)
{
    if (bInitialized)
    {
        return true;
    }
    
    /* Enable CRC clock using LL (smaller than HAL) */
    LL_AHB1_GRP1_EnableClock(LL_AHB1_GRP1_PERIPH_CRC);
    
    bInitialized = true;
    return true;
}

/**
 * @brief Calculate CRC32 using STM32 hardware CRC peripheral
 * 
 * STM32F1 CRC peripheral characteristics:
 * - Fixed polynomial: 0x04C11DB7 (Ethernet/ZIP polynomial)
 * - Input: 32-bit words only (no byte-level input on F1)
 * - Initial value: 0xFFFFFFFF
 * - No output XOR in hardware
 * 
 * This function handles:
 * - Data alignment to 32-bit boundaries
 * - Trailing bytes (< 4 bytes at end) processed via software
 * 
 * @param pu8Data Pointer to data buffer
 * @param u32Length Data length in bytes
 * @return uint32_t CRC32 value
 */
uint32_t FWCheck_HW_Calculate(const uint8_t* pu8Data, uint32_t u32Length)
{
    uint32_t u32Words;
    uint32_t u32TrailingBytes;
    const uint32_t* pu32Data;
    
    /* Ensure peripheral is initialized */
    if (!bInitialized)
    {
        if (!FWCheck_HW_Init())
        {
            return 0;
        }
    }
    
    /* Reset CRC calculation unit (sets DR to 0xFFFFFFFF) */
    LL_CRC_ResetCRCCalculationUnit(CRC);
    
    /* Calculate number of complete 32-bit words */
    u32Words = u32Length / 4;
    u32TrailingBytes = u32Length % 4;
    
    /* Process complete 32-bit words using hardware */
    pu32Data = (const uint32_t*)pu8Data;
    for (uint32_t i = 0; i < u32Words; i++)
    {
        LL_CRC_FeedData32(CRC, pu32Data[i]);
    }
    
    /* Process trailing bytes (if any)
     * STM32F1 doesn't support byte-level CRC input, so we need to
     * pack trailing bytes into a word and feed it
     */
    if (u32TrailingBytes > 0)
    {
        const uint8_t* pu8Trailing = pu8Data + (u32Words * 4);
        uint32_t u32LastWord = 0;
        
        /* Pack trailing bytes into a word (pad with 0x00) */
        for (uint32_t i = 0; i < u32TrailingBytes; i++)
        {
            u32LastWord |= ((uint32_t)pu8Trailing[i]) << (i * 8);
        }
        
        /* Feed the last partial word */
        LL_CRC_FeedData32(CRC, u32LastWord);
    }
    
    return LL_CRC_ReadData32(CRC);
}

#endif /* FWCHECK_USE_HW_CRC */
