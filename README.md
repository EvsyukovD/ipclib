# IPCLib for OCS

This little library was written for my Diploma. It contains functions for interaction with OCS devices (HCU, EAU, AES
modules) of Intel ME of Gigabyte
Brix [GP-BPCE-3350C platform](https://www.gigabyte.com/Mini-PcBarebone/GB-BPCE-3350C-rev-10#ov).

## Required Software & Hardware

For interaction with OCS devices with this lib you should have

1. Gigabyte Brix [GP-BPCE-3350C platform](https://www.gigabyte.com/Mini-PcBarebone/GB-BPCE-3350C-rev-10#ov) with
   modified ME Region. Instructions for modifying ME Region you can find
   in [TXE-PoC](https://github.com/ptresearch/IntelTXE-PoC?tab=readme-ov-file#required-software)).
2. USB debug cable for interacting with Intel ME (as described
   in [TXE-PoC](https://github.com/ptresearch/IntelTXE-PoC?tab=readme-ov-file#required-software))
3. Python 2.7

## Black boxes
I haven't found any official Intel documentation about OCS devices with detailed description of them (meaning of offsets in their address spaces, format of input data for ciphering and etc.). 
So, I considered OCS devices as black boxes.

Despite the given uncertainty, I used some open resources and ROM asm (in my case 80586 arch.) code. 

## Python Modules

Main python modules for interaction with target OCS modules are `rom_aes.py`,
`rom_hcu.py`, `rom_rsa.py`. They were rewritten from ME ROM code.

- `hash(...)` from `rom_hcu.py`. It was expected to hash the plaintext via SHA256, but it produces incorrect results (
  they are not equal to the actual hash value). But they have a fixed length: 160 bits (maybe it’s SHA1?)
- `aes_encrypt_cbc` from `rom_aes.py`. It was expected to encrypt input plaintext via AES cipher with mode CBC. However,
  it always gives zero bit sequence as ciphertext. I don't why it is it. Maybe, it should be executed earlier stages of
  ME loading.
- `rsa_load(...)` from `rom_rsa.py`. In fact, RSA module in Intel ME is EAU (Exponential Acceleration Unit) and given
  function provide modular exponentiation. Degree, modulus and base (data parameter) are 2048 bits.

> [!IMPORTANT]
> EAU (RSA module) memory is very sensitive to read operations. They can change,
> for example, final result of modular exponentiation. That's why, we read result from `0x1ff` offset, not from `0x200`.

> [!IMPORTANT]
> When you power on your platform and execute `hash(...)` function in a first time it can give fixed result, starting with `90bf6...`, no matter input params you specify.
> However, on the next call (with the same input params) it gives normal result, which depends on input parameters.

### Intel Keem Bay
Firstly, I tried to use code from [Linux Intel Keem Bay Driver Code](https://elixir.bootlin.com/linux/latest/source/drivers/crypto/intel/keembay), but I didn't understand mechanism of memory allocation for "dma lists".
My "adaptation" of C code from this driver you can find in `ocs_*.py`, `aes_dev.py`, `hcu_dev.py`, `dev_common.py` modules.

Linux Intel Keem Bay driver can be useful, for example, for understanding meaning of offsets in HCU and AES address spaces.
## Usage

This library based on [ipclib](https://github.com/Roo4L/ipclib), so for establishing DCI connection you can import
ipclib module:`from ipclib import *`.

Examples of `hash(...)`, `aes_encrypt_cbc`, `rsa_load(...)` you can find in their respective Python modules,
in `demo_*(...)` functions.

Offsets for EAU (RSA module) I took from [meloader](https://github.com/peterbjornx/meloader/tree/pchemu).

## Resources
- [ipclib](https://github.com/Roo4L/ipclib)
- [TXE-PoC](https://github.com/ptresearch/IntelTXE-PoC)
- [Linux Intel Keem Bay Driver Code](https://elixir.bootlin.com/linux/latest/source/drivers/crypto/intel/keembay)
- [meloader](https://github.com/peterbjornx/meloader/tree/pchemu)