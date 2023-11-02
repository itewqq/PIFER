#!/bin/bash

JLinkGDBServer -port 3333 -device nrf52 -strict -timeout 0 -nogui -if swd -speed 4000 -endian little -s