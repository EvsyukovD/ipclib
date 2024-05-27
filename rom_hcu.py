from ocs_hcu_interaction import *
from dev_common import *

HCU_BASE = 0xf510b000


class hcu_key(object):
    def __init__(self):
        self.key = None
        self.location = 0  # key in memory


class hcu_out(object):
    def __init__(self):
        self.out = None
        self.location = 0  # output in memory


def read_hash(dgst, dgst_len):

    n = dgst_len // 4  # dgst_len / sizeof(u32)
    mask_8_bit = bit_mask(8)
    block_size = 4  # bytes in 1 block
    for i in range(n):
        chain32 = readl(HCU_BASE + OCS_HCU_CHAIN)
        dgst[i * block_size + 3] = chain32 & mask_8_bit  # 0 bytes
        chain32 = chain32 >> 8
        dgst[block_size * i + 2] = chain32 & mask_8_bit  # 1 byte
        chain32 = chain32 >> 8
        dgst[block_size * i + 1] = chain32 & mask_8_bit  # 2 byte
        chain32 = chain32 >> 8
        dgst[block_size * i] = chain32 & mask_8_bit  # 3 byte

    return 0


def hcu_cfg(key_object, a2):
    v2 = 0x020000

    if a2 & 1 != 0:
        v2 = 0x120000
    v3 = v2 & 0x3FFFFFF | 0x28000000
    result = v2 & 0x3FFFFFF | 0xA8000000  # endianess
    if a2 & 2 != 0:
        iowrite32(7, HCU_BASE + OCS_HCU_KEY_BYTE_ORDER_CFG)
        result = v3 | 0x80400000
    iowrite32(result, HCU_BASE + OCS_HCU_MODE)
    if a2 & 2 != 0 and not (key_object is None):
        if key_object.location != 0:
            log("[DEBUG] Unsupported key location!")
            return -EINVAL
        result = write_hcu_key(key_object.key, len(key_object.key))
    iowrite32(OCS_HCU_START, HCU_BASE + OCS_HCU_OPERATION)
    return result


def wait_and_return_ocs_hcu_isr():
    while True:
        result = ioread32(HCU_BASE + OCS_HCU_ISR)
        if result & 4 != 0:
            return result


def terminate_and_wait():
    iowrite32(2, HCU_BASE + OCS_HCU_OPERATION)  # 2 - terminate hcu
    return wait_and_return_ocs_hcu_isr()


def hash(output, data):
    HCU_INBUFFER_FIFO_OFFSET = 0x600
    hcu_cfg(None, 0)
    terminate_and_wait()
    write_data_to_one_addr(HCU_BASE + HCU_INBUFFER_FIFO_OFFSET, data, len(data))

    if output.location != 0:  # cur realization doesn't support work with sks
        log("[DEBUG] Unsupported output location!")
        return -EINVAL
    return read_hash(output.out, len(output.out))


def load_dma_addresses(a1, dma_src_addr, dma_dst_size, a4, a5):
    iowrite32(dma_src_addr, HCU_BASE + 0x400)  # data address
    if a1 != 0:
        iowrite32(dma_dst_size, HCU_BASE + 0x40C)
        iowrite32(a1, HCU_BASE + 0x404)
    else:
        iowrite32(0, HCU_BASE + 0x40C)
        iowrite32(0, HCU_BASE + 0x404)
    iowrite32(dma_dst_size, HCU_BASE + 0x408)  # dst size
    dma_mode = 0x80000000
    if a4 != 0:
        dma_mode = 0xC8000000
    iowrite32(dma_mode, HCU_BASE + 0x410)  # terminate flag
    return dma_mode


def wait_dma():
    while True:
        res = (ioread32(HCU_BASE + 0x410) & 0xff000000) >> 24
        log("[DEBUG] wait dma res = %s" % str(hex(res)))
        if res != 0:
            return res


def write_hcu_key(key, length):
    # In my implementation I represent key-buffer as array of 8-bit values
    key_u8 = [0] * OCS_HCU_HW_KEY_LEN

    if length > OCS_HCU_HW_KEY_LEN:
        return -EINVAL

    # Copy key into temporary u8 array.
    for i in range(length):
        key_u8[i] = key[i]

    '''
    /*
     * Hardware requires all the bytes of the HW Key vector to be
     * written. So pad with zero until we reach OCS_HCU_HW_KEY_LEN.
     */
    '''
    for i in range(length, OCS_HCU_HW_KEY_LEN):
        key_u8[i] = 0

    '''
    /*
     * OCS hardware expects the MSB of the key to be written at the highest
     * address of the HCU Key vector; in other word, the key must be
     * written in reverse order.
     *
     * Therefore, we first enable byte swapping for the HCU key vector;
     * so that bytes of 32-bit word written to OCS_HCU_KEY_[0..15] will be
     * swapped:
     * 3 <---> 0, 2 <---> 1.
     */
    '''
    writel(HCU_BYTE_ORDER_SWAP, HCU_BASE + OCS_HCU_KEY_BYTE_ORDER_CFG)

    '''
    /*
     * And then we write the 32-bit words composing the key starting from
     * the end of the key.
     */
    '''
    block_size = 4  # 4 bytes in 1 block, sizeof(u32)
    for i in range(OCS_HCU_HW_KEY_LEN_U32):
        value_32_bit = 0
        value_32_bit |= key_u8[OCS_HCU_HW_KEY_LEN - 1 - i * block_size - 3]  # 3 byte
        value_32_bit = value_32_bit << 8
        value_32_bit |= key_u8[OCS_HCU_HW_KEY_LEN - 1 - i * block_size - 2]  # 2 byte
        value_32_bit = value_32_bit << 8
        value_32_bit |= key_u8[OCS_HCU_HW_KEY_LEN - 1 - i * block_size - 1]  # 1 byte
        value_32_bit = value_32_bit << 8
        value_32_bit |= key_u8[OCS_HCU_HW_KEY_LEN - 1 - i * block_size]  # 0 byte

        writel(value_32_bit, HCU_BASE + OCS_HCU_KEY_0 + 4 * i)

    for i in range(length, OCS_HCU_HW_KEY_LEN):
        key_u8[i] = 0

    return 0


def sha256(dma_addresses, flags):
    if flags & 1 != 0:
        hcu_cfg(None, 0)
    res = dma_addresses[0]
    if dma_addresses[0] != 0:
        load_dma_addresses(0, dma_addresses[1], dma_addresses[0], 0, 0)
        wait_dma()
    if flags & 4 != 0:
        res = terminate_and_wait()
    return res


def rom_hmac_derive_key(key_object, output, sks_cfg, data):
    HCU_INBUFFER_FIFO_OFFSET = 0x600
    hcu_cfg(key_object, 2)
    write_data_to_one_addr(HCU_BASE + HCU_INBUFFER_FIFO_OFFSET, data, len(data))
    if output.location != 0:  # cur realization doesn't support work with sks
        log("[DEBUG] Unsupported output location!")
        return -EINVAL
    output.out = bytearray(ocs_hcu_digest_size(ocs_hcu_algo.OCS_HCU_ALGO_SHA512))
    return read_hash(output.out, len(output.out))


def hash_data(data):
    output = hcu_out()
    output.out = bytearray(20)
    data = bytearray('A' * 19)
    t.halt()

    hash(output, data)

    dgst = output.out

    print('Hash:')
    print(''.join(format(x, '02x') for x in dgst))
