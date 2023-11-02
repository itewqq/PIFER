target extended-remote localhost:3333

layout asm
focus cmd

# monitor reset halt
# b *0x080017B0
# b *0x080003C8
# b *0x08000448
# b *0x08001850

# b *0x0bd0
# b *0x0696
# b *0x03EC
# b *0x03EE

# zeypher on nrf52
b *0x3F8
b *0xb70
# b *0x1702
# b *0x33dc # already weird
# b *0x34a4
# watch *0x10001208
# SetWP 0x10001208 W