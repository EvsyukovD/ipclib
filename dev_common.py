from utils import *
from mem import phys, dma_alloc, log, malloc
import logging
from asm import *
from cse_controller import *

cse = CSEController(t)

EINVAL = 22
EIO = 5
ENOMEM = 12
ETIMEDOUT = 110
EOVERFLOW = 112
EBADMSG = 84

DMA_BIDIRECTIONAL = 0
DMA_TO_DEVICE = 1
DMA_FROM_DEVICE = 2
DMA_NONE = 3

IRQ_HANDLED = (1 << 0)
IRQ_NONE = 1


def bit_mask(mask_len):
    return (1 << mask_len) - 1


def bit(bit_number):
    if bit_number == 0:
        return 1
    return 1 << bit_number


def swab32(x):
    '''
    Write x as little-endian 32-bit value
    :param x:
    :return: 32-bit little-endian value
    '''
    res = 0
    res |= ((x & 0x000000ff) << 24)
    res |= ((x & 0x0000ff00) << 8)
    res |= ((x & 0x00ff0000) >> 8)
    res |= ((x & 0xff000000) >> 24)
    return res


DMA_MAPPING_ERROR = bit_mask(64)


def halt_and_check_sts(thread):
    flag = thread.isrunning()
    # thread.halt()
    return flag


def go_if_need(thread, prev_sts):
    thread_running = True
    # if prev_sts == thread_running:
    # thread.go()
    pass


def resume_if_need(prev_sts):
    thread_running = True
    if prev_sts == thread_running:
        t.go()


def read_byte_via_bup(addr):
    execute_asm(t,
                "mov eax, ds:%s" % hex(addr).replace("L", ""))
    # wait_until_infinite_loop(t, False)
    return reg("eax")


'''
Wrap for memory dumping
'''


def memdump(addr, size, data_size):
    flag = halt_and_check_sts(t)
    t.memdump(phys(addr), size, data_size)
    go_if_need(t, flag)


'''
Write 32 bit value to the physical address
'''


def writel(value, address):
    flag = halt_and_check_sts(t)

    mask_32_bit = bit_mask(32)
    value = value & mask_32_bit
    bit_data = ipc.BitData(32, value)
    t.memblock(phys(address), 4, 1, bit_data.ToRawBytes())

    go_if_need(t, flag)


'''
Read 32 bit value to the physical address
'''


def readl(address):
    flag = halt_and_check_sts(t)

    ret_val = int(t.memblock(phys(address), 4, 1))

    go_if_need(t, flag)
    return ret_val


'''
Write 8 bit value to the physical address
'''


def writeb(value, address):
    flag = halt_and_check_sts(t)

    mask_8_bit = bit_mask(8)
    value = int(value) & mask_8_bit
    bit_data = ipc.BitData(8, value)
    t.memblock(phys(address), 1, 1, bit_data.ToRawBytes())

    go_if_need(t, flag)


def readb(address):
    flag = halt_and_check_sts(t)

    ret_val = int(t.memblock(phys(address), 1, 1))

    go_if_need(t, flag)
    return ret_val


'''
Write 32 bit value to the physical address
'''


def iowrite32(value, address):
    writel(value, address)


'''
Read 32 bit value to the physical address
'''


def ioread32(address):
    return readl(address)


'''
Write 8 bit value to the physical address
'''


def iowrite8(value, address):
    writeb(value, address)


'''
Read 8 bit value to the physical address
'''


def ioread8(address):
    return readb(address)


def write_data(data, address):
    data_len = len(data)
    for i in range(data_len):
        iowrite8(data[i], address + i)


def write_data_32(data, address):
    block_size = 4
    data_len_u32 = len(data) // block_size
    for i in range(data_len_u32):
        val_32 = data[i * block_size]
        val_32 <<= 8
        val_32 |= data[i * block_size + 1]
        val_32 <<= 8
        val_32 |= data[i * block_size + 2]
        val_32 <<= 8
        val_32 |= data[i * block_size + 3]
        iowrite32(val_32, address + i * block_size)


def next_address(data_len_bytes=0, start_address=0):
    ret_address = start_address
    while True:
        yield ret_address
        ret_address += data_len_bytes


'''
Put data bytes in rewritable memory
'''


def alloc_bytes(data_bytes, length, start=0):
    start_address = next(next_address(length, start))
    log("[DEBUG] Allocate memory %d bytes and get address %s" % (length, str(hex(start_address))))
    for i in range(length):
        iowrite8(data_bytes[i], start_address + i)
    return start_address


def write_data_to_one_addr(address, data, data_len):
    data_len_u32 = data_len // 4
    for i in range(0, data_len_u32, 4):
        val_32 = data[i]
        val_32 <<= 8
        val_32 |= data[i + 1]
        val_32 <<= 8
        val_32 |= data[i + 2]
        val_32 <<= 8
        val_32 |= data[i + 3]
        iowrite32(val_32, address)
    rest = data_len % 4
    start = data_len - rest
    for i in range(rest):
        iowrite8(data[i + start], address)


def write_data_to_one_addr8(address, data, data_len):
    for i in data:
        iowrite8(i, address)


def to_bytes(n, length=1, byteorder='big', signed=False):
    if byteorder == 'little':
        order = range(length)
    elif byteorder == 'big':
        order = reversed(range(length))
    else:
        raise ValueError("byteorder must be either 'little' or 'big'")

    return bytes((n >> i * 8) & 0xff for i in order)


def to_bytearray(n, length=1, byteorder='big', signed=False, res=None):
    if byteorder == 'little':
        order = range(length)
    elif byteorder == 'big':
        order = reversed(range(length))
    else:
        raise ValueError("byteorder must be either 'little' or 'big'")
    if not (res is None):
        for i in order:
            res[i] = (n >> i * 8) & 0xff
        return res
    else:
        return bytearray((n >> i * 8) & 0xff for i in order)


def convert_bytes_to_hex_str(arr):
    return ''.join(format(x, '02x') for x in arr)
