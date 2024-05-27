from ocs_aes_interaction import *


AES_BASE = 0xf5108000

AES_A_BASE = 0xf510A000


class key_struct(object):
    def __init__(self):
        self.key = None
        self.use_sks = False


'''
Configure AES via key_struct, iv (CBC mode) and command: 1 - encrypt, 0 - decrypt
'''


def aes_cfg_cbc(key_st, iv, command):
    result = 0
    key = key_st.key
    key_len = len(key)

    # Configure byte order
    iowrite32(0x7ff, AES_BASE + AES_BYTE_ORDER_CFG_OFFSET)

    v3 = ((command ^ 1) & 3) << 6
    v3 |= 1 << 8  # Set CBC mode

    # Load command
    iowrite32(v3, AES_BASE + AES_COMMAND_OFFSET)

    # Log AES status reg

    status = ioread32(AES_BASE + AES_STATUS_OFFSET)
    log("[DEBUG] STATUS value: %s" % str(hex(status)))

    # Load IV
    cur_addr = AES_BASE + AES_IV_0_OFFSET
    for i in range(len(iv)):
        iowrite8(iv[i], cur_addr)
        cur_addr += 1
    use_sks = key_st.use_sks
    if use_sks:
        log("[DEBUG] This code doesn't support sks interaction!")
        return -EINVAL
    else:
        result = 0

        # Load key
        cur_addr = AES_BASE + AES_KEY_0_OFFSET
        for i in range(0, key_len, 4):
            key_32 = key[i]
            key_32 <<= 8
            key_32 |= key[i + 1]
            key_32 <<= 8
            key_32 |= key[i + 2]
            key_32 <<= 8
            key_32 |= key[i + 3]
            iowrite32(key_32, cur_addr)
            cur_addr += 4
    if not use_sks or result & 8 == 0:
        if key_len != 16:
            result = 1
        else:
            result = 0
        iowrite32(result, AES_BASE + AES_KEY_SIZE_OFFSET)
    iowrite32(AES_BASE + AES_ACTIVE_OFFSET, 1)
    return result


def wait_aes():
    log("[DEBUG] Waiting AES...")
    while True:
        result = ioread32(AES_BASE + AES_ISR_OFFSET)
        if result & 2 == 0:
            return result
        usleep(1000000)


def aes_encrypt_cbc(key_st, data, out, iv):
    # Configure AES
    aes_cfg_cbc(key_st, iv, 1)  # encrypt

    # Load data
    block_size = 4  # sizeof(u32)
    data_len_32 = len(data) // block_size  # len(data) always equal 4 * s, where s is natural num
    for i in range(0, data_len_32, 4):
        data_32 = data[i]
        data_32 <<= 8
        data_32 |= data[i + 1]
        data_32 <<= 8
        data_32 |= data[i + 2]
        data_32 <<= 8
        data_32 |= data[i + 3]
        iowrite32(data_32, AES_BASE + AES_A_DMA_INBUFFER_WRITE_FIFO_OFFSET)

    val = ioread32(AES_BASE + AES_ACTIVE_OFFSET)
    val |= 2  # aes terminate
    iowrite32(val, AES_BASE + AES_ACTIVE_OFFSET)

    wait_aes()

    # Get result
    mask_8 = bit_mask(8)
    out_len_32 = len(out) // 4
    for i in range(3, out_len_32, 4):
        out_32 = ioread32(AES_BASE + AES_A_DMA_OUTBUFFER_READ_FIFO_OFFSET)
        out[i] = out_32 & mask_8
        out_32 = out_32 >> 8
        out[i - 1] = out_32 & mask_8
        out_32 = out_32 >> 8
        out[i - 2] = out_32 & mask_8
        out_32 = out_32 >> 8
        out[i - 3] = out_32 & mask_8


def isr_enable():
    isr_val = ioread32(AES_BASE + AES_ISR_OFFSET)
    isr_val |= 2
    iowrite32(isr_val, AES_BASE + AES_ISR_OFFSET)
    t.memdump(phys(AES_BASE + AES_ISR_OFFSET), 4, 1)


def demo_aes_encrypt():
    # Demo data, key, iv
    data = bytearray('\xff' * 16)
    out = bytearray(16)
    key = bytearray([0xff] * 16)
    iv = bytearray([0xff] * 16)
    key_st = key_struct()
    key_st.key = key
    key_st.use_sks = False

    t.halt()

    # Output ciphertext is always zero bit sequence (idk why :( )
    aes_encrypt_cbc(key_st, data, out, iv)

    print("Data:")
    print(''.join(format(x, '02x') for x in data))

    print("Key:")
    print(''.join(format(x, '02x') for x in key))

    print("IV:")
    print(''.join(format(x, '02x') for x in iv))


    print("Output:")
    print(''.join(format(x, '02x') for x in out))
