#!/bin/bash
set -x

BIN_PATH=$1

# st-flash --format 'binary' write $BIN_PATH 0x08000000
# /home/itemqq/STM32CubeProgrammer/bin/STM32_Programmer_CLI --download $BIN_PATH 0x08000000
openocd -f  interface/stlink.cfg -f target/stm32l0.cfg -c "program $BIN_PATH exit 0x8000000"