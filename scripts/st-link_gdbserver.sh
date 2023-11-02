#!/bin/bash

st-util -m -u -p 3333 # reset
# st-util -v -m -n -p 3333 # not-reset

# openocd -f  interface/stlink.cfg -f target/stm32l0.cfg -c "program $BIN_PATH exit 0x8000000"