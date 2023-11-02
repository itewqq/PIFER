#!/bin/bash

openocd -f ./interface/jlink.cfg -c "transport select swd" -f ./target/nrf52.cfg