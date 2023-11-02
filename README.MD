# PIFER

## Intro

A fine-grained static binary instrumenting framework for bare-metal ARM firmware.

## Install

1. Download/Clone the repository.
2. Install `GNU Arm Embedded Toolchain` on you OS and make sure the `arm-none-eabi*` tools exist in your `PATH`.
3. Install python dependencies `pip install -r requirements.txt`.
4. For test, `cd src && python example.py`

## Usage

`PIFER` is designed to provide basic instruction-level instrument functionality that can support any higher level applications. 

PIFER provides a easy-to-use python interfaces:

```python
import pifer

p = PIFER(bin_path=bin_path, img_base=img_base, arch=mcpu, compile_options=compile_options)

```

Note that the following parameters are required to initialize the object:

- `bin_path`: The path to the raw binary firmware (.bin) to be instrumented. 
  - If you have `.axf` or `.elf` only, use `arm-none-eabi-objcopy` to produce the `.bin` file.
- `img_base`: The address where the binary locate in the memory of the chip.
- `mcpu`: Target architecture (e.g., 'cortex-m4').
- `compile_options`: Extra compilation options. For example to hook FPU related instructions you may need to use: "-mfpu=fpv5-sp-d16 -mfloat-abi=hard"

Next, add the target addresses and corresponding instrument code using the `add_addr_and_payload(addr, payload)` interface.

```python
target_list = [0x07D4, 0x0806, 0x0832] 

for addr in target_list:
    payload = f"MOV R1, R1\n"
    p.add_addr_and_payload(addr, payload)
```

Finnaly, call the `patch` method to perform the instrumentation:

```python
p.patch()
```

Here's a complete example in [src/example.py](src/example.py), which instrument the blnky firmware for the LPC55S69-EVK.

<details><summary>example.py</summary>
<p>

```python
from pifer import *

# Configurations
bin_path = "../binaries/lpcxpresso55s69_led_blinky.bin"
img_base = 0
mcpu = "cortex-m33"
compile_options = "-mfpu=fpv5-sp-d16 -mfloat-abi=hard"
p = PIFER(bin_path=bin_path, img_base=img_base, arch=mcpu, compile_options=compile_options)

# Set the target
'''
.text:000007D4 80 B5                       PUSH            {R7,LR}

.text:00000806 0C 4B                       LDR             R3, =_data

.text:00000832 F5 E7                       B               loc_820
'''
target_list = [0x07D4, 0x0806, 0x0832] 

for addr in target_list:
    payload = f"MOV R1, R1\n"
    p.add_addr_and_payload(addr, payload)

p.patch()

print(f"Done")
```

</p>
</details>
