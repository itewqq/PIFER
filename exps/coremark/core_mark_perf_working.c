/*
 * Copyright (c) 2013 - 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"

#include "fsl_power.h"
#include "core_main.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
int get_counter(){
	int value;
	asm volatile (
		"mov r0, 0x0\n\t"
		"ldr r0, [r0, #0]\n\t"
		"ldr r0, [r0, #0xC]\n\t"
		"mov %[value], r0"
		: [value] "+r" (value));
	return value;
}

int set_counter(int value){
	asm volatile (
		"mov r0, 0x0\n\t"
		"ldr r0, [r0, #0]\n\t"
		"str %[value], [r0, #0xC]\n\t"
		: [value] "+r" (value));
	return value;
}

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Main function
 */
int main(void)
{

    /* Init board hardware. */
    /* set BOD VBAT level to 1.65V */
    POWER_SetBodVbatLevel(kPOWER_BodVbatLevel1650mv, kPOWER_BodHystLevel50mv, false);
    /* attach main clock divide to FLEXCOMM0 (debug console) */
    CLOCK_AttachClk(BOARD_DEBUG_UART_CLK_ATTACH);

    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();
#if !defined(DONT_ENABLE_FLASH_PREFETCH)
    /* enable flash prefetch for better performance */
    SYSCON->FMCCR |= SYSCON_FMCCR_PREFEN_MASK;
#endif


    char ch;
    int value = 0, round = 0;
    while (1)
    {
//    	GPIO_PinWrite(GPIO, BOARD_INITPINS_MY_TRIGGER_START_PORT, BOARD_INITPINS_MY_TRIGGER_START_PIN, 0);
    	asm volatile (
				"LDR             R0, =0x4008C000\n\t"
				"MOV             R1, #0\n\t"
				"STRB            R1, [R0,#0xF]");
//    	GPIO_PinWrite(GPIO, BOARD_INITPINS_MY_TRIGGER_END_PORT, BOARD_INITPINS_MY_TRIGGER_END_PIN, 0);
    	asm volatile (
				"LDR             R0, =0x4008C000\n\t"
				"MOV             R1, #0\n\t"
				"STRB            R1, [R0,#0x12]");

    	set_counter(value);

        ch = GETCHAR();

//        GPIO_PinWrite(GPIO, BOARD_INITPINS_MY_TRIGGER_START_PORT, BOARD_INITPINS_MY_TRIGGER_START_PIN, 1);
    	asm volatile (
				"LDR             R0, =0x4008C000\n\t"
				"MOV             R1, #1\n\t"
				"STRB            R1, [R0,#0xF]");
        int result = core_main(0, 0);
//        GPIO_PinWrite(GPIO, BOARD_INITPINS_MY_TRIGGER_END_PORT, BOARD_INITPINS_MY_TRIGGER_END_PIN, 1);
    	asm volatile (
				"LDR             R0, =0x4008C000\n\t"
				"MOV             R1, #1\n\t"
				"STRB            R1, [R0,#0x12]");

        value = get_counter();
        PRINTF("Round %d, hit times: %d\n", round, value);
        value = 0;
        round++;
    }
}
