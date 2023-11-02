#!/bin/bash
set -x

BIN_PATH=$1

openocd -f interface/cmsis-dap.cfg -f target/stm32f1x.cfg -c "program $BIN_PATH exit 0x8000000"

