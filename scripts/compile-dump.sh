#!/bin/bash
arm-none-eabi-as -mthumb  -mcpu=cortex-m7  svc_handler.S 
arm-none-eabi-objdump -D a.out >> a.dis
