# .text:0000082E 00 F0 96 FF                 BL              GPIO_PortToggle


python pifer.py -p "../binaries/lpcxpresso55s69_led_blinky.bin" -b 0x0 -t 0x0000082E -a cortex-m33


# .text:00001BA2 00 D0                       BEQ             loc_1BA6

python pifer.py -p "../binaries/lpcxpresso55s69_CoreMark.bin" -b 0x0 -t 0x00001BA2 -a cortex-m33
