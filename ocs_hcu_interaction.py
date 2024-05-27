# https://elixir.bootlin.com/linux/latest/source/drivers/crypto/intel/keembay/ocs-hcu.c

from ocs_hcu_classes import *
from dev_common import *
from utils import log
import time

usleep = lambda x: time.sleep(x / 1000000.0)

# Registers.
OCS_HCU_MODE = 0x00
OCS_HCU_CHAIN = 0x04
OCS_HCU_OPERATION = 0x08
OCS_HCU_KEY_0 = 0x0C
OCS_HCU_ISR = 0x50
OCS_HCU_IER = 0x54
OCS_HCU_STATUS = 0x58
OCS_HCU_MSG_LEN_LO = 0x60
OCS_HCU_MSG_LEN_HI = 0x64
OCS_HCU_KEY_BYTE_ORDER_CFG = 0x80
OCS_HCU_DMA_SRC_ADDR = 0x400
OCS_HCU_DMA_SRC_SIZE = 0x408
OCS_HCU_DMA_DST_SIZE = 0x40C
OCS_HCU_DMA_DMA_MODE = 0x410
OCS_HCU_DMA_NEXT_SRC_DESCR = 0x418
OCS_HCU_DMA_MSI_ISR = 0x480
OCS_HCU_DMA_MSI_IER = 0x484
OCS_HCU_DMA_MSI_MASK = 0x488

# Register bit definitions.
HCU_MODE_ALGO_SHIFT = 16
HCU_MODE_HMAC_SHIFT = 22
HCU_STATUS_BUSY = bit(0)
HCU_BYTE_ORDER_SWAP = bit(0)
HCU_IRQ_HASH_DONE = bit(2)
HCU_IRQ_HASH_ERR_MASK = (bit(3) | bit(1) | bit(0))
HCU_DMA_IRQ_SRC_DONE = bit(0)
HCU_DMA_IRQ_SAI_ERR = bit(2)
HCU_DMA_IRQ_BAD_COMP_ERR = bit(3)
HCU_DMA_IRQ_INBUF_RD_ERR = bit(4)
HCU_DMA_IRQ_INBUF_WD_ERR = bit(5)
HCU_DMA_IRQ_OUTBUF_WR_ERR = bit(6)
HCU_DMA_IRQ_OUTBUF_RD_ERR = bit(7)
HCU_DMA_IRQ_CRD_ERR = bit(8)

HCU_DMA_IRQ_ERR_MASK = (HCU_DMA_IRQ_SAI_ERR |
                        HCU_DMA_IRQ_BAD_COMP_ERR |
                        HCU_DMA_IRQ_INBUF_RD_ERR |
                        HCU_DMA_IRQ_INBUF_WD_ERR |
                        HCU_DMA_IRQ_OUTBUF_WR_ERR |
                        HCU_DMA_IRQ_OUTBUF_RD_ERR |
                        HCU_DMA_IRQ_CRD_ERR)

HCU_DMA_SNOOP_MASK = (0x7 << 28)
HCU_DMA_SRC_LL_EN = bit(25)
HCU_DMA_EN = bit(31)
OCS_HCU_ENDIANNESS_VALUE = 0x2A
HCU_DMA_MSI_UNMASK = bit(0)
HCU_DMA_MSI_DISABLE = 0
HCU_IRQ_DISABLE = 0
OCS_HCU_START = bit(0)
OCS_HCU_TERMINATE = bit(1)
OCS_LL_DMA_FLAG_TERMINATE = bit(31)

OCS_HCU_HW_KEY_LEN_U32 = (OCS_HCU_HW_KEY_LEN // 4)

HCU_DATA_WRITE_ENDIANNESS_OFFSET = 26

OCS_HCU_NUM_CHAINS_SHA256_224_SM3 = (SHA256_DIGEST_SIZE // 4)
OCS_HCU_NUM_CHAINS_SHA384_512 = (SHA512_DIGEST_SIZE // 4)

'''
/*
 * While polling on a busy HCU, wait maximum 200us between one check and the
 * other.
 */
'''
OCS_HCU_WAIT_BUSY_RETRY_DELAY_US = 200
# Wait on a busy HCU for maximum 1 second.
OCS_HCU_WAIT_BUSY_TIMEOUT_US = 1000000


def ocs_hcu_num_chains(algo):
    if algo == ocs_hcu_algo.OCS_HCU_ALGO_SHA224 or \
            algo == ocs_hcu_algo.OCS_HCU_ALGO_SHA256 or \
            algo == ocs_hcu_algo.OCS_HCU_ALGO_SM3:
        return OCS_HCU_NUM_CHAINS_SHA256_224_SM3
    if algo == ocs_hcu_algo.OCS_HCU_ALGO_SHA384 or \
            algo == ocs_hcu_algo.OCS_HCU_ALGO_SHA512:
        return OCS_HCU_NUM_CHAINS_SHA384_512
    return 0


def ocs_hcu_digest_size(algo):
    if algo == ocs_hcu_algo.OCS_HCU_ALGO_SHA1:
        return SHA1_DIGEST_SIZE
    if algo == ocs_hcu_algo.OCS_HCU_ALGO_SHA224:
        return SHA224_DIGEST_SIZE
    if algo == ocs_hcu_algo.OCS_HCU_ALGO_SM3 or \
            algo == ocs_hcu_algo.OCS_HCU_ALGO_SHA256:
        return SHA256_DIGEST_SIZE
    if algo == ocs_hcu_algo.OCS_HCU_ALGO_SHA384:
        return SHA384_DIGEST_SIZE
    if algo == ocs_hcu_algo.OCS_HCU_ALGO_SHA512:
        return SHA512_DIGEST_SIZE
    return 0


'''
/**
 * ocs_hcu_wait_busy() - Wait for HCU OCS hardware to became usable.
 * @hcu_dev:	OCS HCU device to wait for.
 *
 * Return: 0 if device free, -ETIMEOUT if device busy and internal timeout has
 *	   expired.
 */
'''


def ocs_hcu_wait_busy(hcu_dev):
    # TO DO: realize this wait function
    retry_time_sec = OCS_HCU_WAIT_BUSY_RETRY_DELAY_US / 1000000.0
    us_sum = 0
    #log("[DEBUG] Dumping hcu status memory:")
    #memdump(hcu_dev.io_base + OCS_HCU_STATUS, 4, 1)
    log("[DEBUG] Waiting for hcu ...")
    while True:
        #val = readl(hcu_dev.io_base + OCS_HCU_STATUS)
        #if not(val & HCU_STATUS_BUSY):
        #    return 0
        usleep(retry_time_sec)
        us_sum += OCS_HCU_WAIT_BUSY_RETRY_DELAY_US
        if us_sum % 100000 == 0:
           log("[DEBUG] Total waiting time is %s us" % us_sum)
        if us_sum >= OCS_HCU_WAIT_BUSY_TIMEOUT_US:
            log("[DEBUG] Waiting time is out")
            val = readl(hcu_dev.io_base + OCS_HCU_STATUS)
            if not(val & HCU_STATUS_BUSY):
               return 0
            return 0#-ETIMEDOUT


def ocs_hcu_done_irq_en(hcu_dev):
    # Clear any pending interrupts.
    writel(0xFFFFFFFF, hcu_dev.io_base + OCS_HCU_ISR)
    hcu_dev.irq_err = False
    # Enable error and HCU done interrupts.
    writel(HCU_IRQ_HASH_DONE | HCU_IRQ_HASH_ERR_MASK,
           hcu_dev.io_base + OCS_HCU_IER)


def ocs_hcu_dma_irq_en(hcu_dev):
    # Clear any pending interrupts.
    writel(0xFFFFFFFF, hcu_dev.io_base + OCS_HCU_DMA_MSI_ISR)
    hcu_dev.irq_err = False
    # Only operating on DMA source completion and error interrupts.
    writel(HCU_DMA_IRQ_ERR_MASK | HCU_DMA_IRQ_SRC_DONE,
           hcu_dev.io_base + OCS_HCU_DMA_MSI_IER)
    # Unmask
    writel(HCU_DMA_MSI_UNMASK, hcu_dev.io_base + OCS_HCU_DMA_MSI_MASK)


def ocs_hcu_irq_dis(hcu_dev):
    writel(HCU_IRQ_DISABLE, hcu_dev.io_base + OCS_HCU_IER)
    writel(HCU_DMA_MSI_DISABLE, hcu_dev.io_base + OCS_HCU_DMA_MSI_IER)


def ocs_hcu_wait_and_disable_irq(hcu_dev):
    # TO DO: realize this func
    ocs_hcu_irq_dis(hcu_dev)
    return 0


'''
/**
 * ocs_hcu_get_intermediate_data() - Get intermediate data.
 * @hcu_dev:	The target HCU device.
 * @data:	Where to store the intermediate.
 * @algo:	The algorithm being used.
 *
 * This function is used to save the current hashing process state in order to
 * continue it in the future.
 *
 * Note: once all data has been processed, the intermediate data actually
 * contains the hashing result. So this function is also used to retrieve the
 * final result of a hashing process.
 *
 * Return: 0 on success, negative error code otherwise.
 */
'''


def ocs_hcu_get_intermediate_data(hcu_dev,
                                  data,
                                  algo):
    n = ocs_hcu_num_chains(algo)

    # Data not requested.
    if data is None:
        return -EINVAL

    # chain8 = data.digest  # bytearray

    # Ensure that the OCS is no longer busy before reading the chains.
    rc = ocs_hcu_wait_busy(hcu_dev)
    if rc != 0:
        return rc

    '''
    /*
	 * This loops is safe because data->digest is an array of
	 * SHA512_DIGEST_SIZE bytes and the maximum value returned by
	 * ocs_hcu_num_chains() is OCS_HCU_NUM_CHAINS_SHA384_512 which is equal
	 * to SHA512_DIGEST_SIZE / sizeof(u32).
	 */
    '''
    mask_8_bit = bit_mask(8)
    block_size = 4  # bytes in 1 block
    for i in range(n):
        chain32 = readl(hcu_dev.io_base + OCS_HCU_CHAIN)
        data.digest[i * block_size + 3] = chain32 & mask_8_bit  # 0 bytes
        chain32 = chain32 >> 8
        data.digest[block_size * i + 2] = chain32 & mask_8_bit  # 1 byte
        chain32 = chain32 >> 8
        data.digest[block_size * i + 1] = chain32 & mask_8_bit  # 2 byte
        chain32 = chain32 >> 8
        data.digest[block_size * i] = chain32 & mask_8_bit  # 3 byte

    data.msg_len_lo = readl(hcu_dev.io_base + OCS_HCU_MSG_LEN_LO)
    data.msg_len_hi = readl(hcu_dev.io_base + OCS_HCU_MSG_LEN_HI)
    return 0


'''
/**
 * ocs_hcu_set_intermediate_data() - Set intermediate data.
 * @hcu_dev:	The target HCU device.
 * @data:	The intermediate data to be set.
 * @algo:	The algorithm being used.
 *
 * This function is used to continue a previous hashing process.
 */
'''


def ocs_hcu_set_intermediate_data(hcu_dev,
                                  data,
                                  algo):
    n = ocs_hcu_num_chains(algo)

    '''
    /*
	 * This loops is safe because data->digest is an array of
	 * SHA512_DIGEST_SIZE bytes and the maximum value returned by
	 * ocs_hcu_num_chains() is OCS_HCU_NUM_CHAINS_SHA384_512 which is equal
	 * to SHA512_DIGEST_SIZE / sizeof(u32).
	 */
    '''
    block_size = 4
    for i in range(n):
        value_32_bit = data.digest[i * block_size]  # 3 byte
        value_32_bit = value_32_bit << 8
        value_32_bit |= data.digest[i * block_size + 1]  # 2 byte
        value_32_bit = value_32_bit << 8
        value_32_bit |= data.digest[i * block_size + 2]  # 1 byte
        value_32_bit = value_32_bit << 8
        value_32_bit |= data.digest[i * block_size + 3]  # 0 byte

        writel(value_32_bit, hcu_dev.io_base + OCS_HCU_CHAIN)

    writel(data.msg_len_lo, hcu_dev.io_base + OCS_HCU_MSG_LEN_LO)
    writel(data.msg_len_hi, hcu_dev.io_base + OCS_HCU_MSG_LEN_HI)


def ocs_hcu_get_digest(hcu_dev,
                       algo,
                       dgst,
                       dgst_len):
    if dgst is None:
        return -EINVAL

    # Length of the output buffer must match the algo digest size.
    if dgst_len != ocs_hcu_digest_size(algo):
        return -EINVAL

    # Ensure that the OCS is no longer busy before reading the chains.
    rc = ocs_hcu_wait_busy(hcu_dev)
    if rc != 0:
        return rc

    n = dgst_len // 4  # dgst_len / sizeof(u32)
    mask_8_bit = bit_mask(8)
    block_size = 4  # bytes in 1 block
    for i in range(n):
        chain32 = readl(hcu_dev.io_base + OCS_HCU_CHAIN)
        dgst[i * block_size + 3] = chain32 & mask_8_bit  # 0 bytes
        chain32 = chain32 >> 8
        dgst[block_size * i + 2] = chain32 & mask_8_bit  # 1 byte
        chain32 = chain32 >> 8
        dgst[block_size * i + 1] = chain32 & mask_8_bit  # 2 byte
        chain32 = chain32 >> 8
        dgst[block_size * i] = chain32 & mask_8_bit  # 3 byte

    return 0


'''
/**
 * ocs_hcu_hw_cfg() - Configure the HCU hardware.
 * @hcu_dev:	The HCU device to configure.
 * @algo:	The algorithm to be used by the HCU device.
 * @use_hmac:	Whether or not HW HMAC should be used.
 *
 * Return: 0 on success, negative error code otherwise.
 */
'''


def ocs_hcu_hw_cfg(hcu_dev,
                   algo,
                   use_hmac):
    if algo != ocs_hcu_algo.OCS_HCU_ALGO_SHA256 and \
            algo != ocs_hcu_algo.OCS_HCU_ALGO_SHA224 and \
            algo != ocs_hcu_algo.OCS_HCU_ALGO_SHA384 and \
            algo != ocs_hcu_algo.OCS_HCU_ALGO_SHA512 and \
            algo != ocs_hcu_algo.OCS_HCU_ALGO_SM3:
        return -EINVAL

    rc = ocs_hcu_wait_busy(hcu_dev)
    if rc != 0:
        return rc

    # Ensure interrupts are disabled.
    ocs_hcu_irq_dis(hcu_dev)

    # Configure endianness, hashing algorithm and HW HMAC( if needed)
    cfg = OCS_HCU_ENDIANNESS_VALUE << HCU_DATA_WRITE_ENDIANNESS_OFFSET
    cfg |= algo << HCU_MODE_ALGO_SHIFT
    if use_hmac:
        cfg |= bit(HCU_MODE_HMAC_SHIFT)

    writel(cfg, hcu_dev.io_base + OCS_HCU_MODE)
    return 0


'''
/**
 * ocs_hcu_clear_key() - Clear key stored in OCS HMAC KEY registers.
 * @hcu_dev:	The OCS HCU device whose key registers should be cleared.
 */
'''


def ocs_hcu_clear_key(hcu_dev):
    for reg_off in range(0, OCS_HCU_HW_KEY_LEN, 4):
        writel(0, hcu_dev.io_base + OCS_HCU_KEY_0 + reg_off)


'''
/**
 * ocs_hcu_write_key() - Write key to OCS HMAC KEY registers.
 * @hcu_dev:	The OCS HCU device the key should be written to.
 * @key:	The key to be written.
 * @len:	The size of the key to write. It must be OCS_HCU_HW_KEY_LEN.
 *
 * Return:	0 on success, negative error code otherwise.
 */
'''


def ocs_hcu_write_key(hcu_dev, key, length):
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
    writel(HCU_BYTE_ORDER_SWAP, hcu_dev.io_base + OCS_HCU_KEY_BYTE_ORDER_CFG)

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

        writel(value_32_bit, hcu_dev.io_base + OCS_HCU_KEY_0 + 4 * i)

    for i in range(length, OCS_HCU_HW_KEY_LEN):
        key_u8[i] = 0

    return 0


'''

/**
 * ocs_hcu_ll_dma_start() - Start OCS HCU hashing via DMA
 * @hcu_dev:	The OCS HCU device to use.
 * @dma_list:	The OCS DMA list mapping the data to hash.
 * @finalize:	Whether or not this is the last hashing operation and therefore
 *		the final hash should be compute even if data is not
 *		block-aligned.
 *
 * Return: 0 on success, negative error code otherwise.
 */
'''


def ocs_hcu_ll_dma_start(hcu_dev,
                         dma_list,
                         finalize):
    cfg = HCU_DMA_SNOOP_MASK | HCU_DMA_SRC_LL_EN | HCU_DMA_EN

    if dma_list is None:
        return -EINVAL

    '''
    /*
	 * For final requests we use HCU_DONE IRQ to be notified when all input
	 * data has been processed by the HCU; however, we cannot do so for
	 * non-final requests, because we don't get a HCU_DONE IRQ when we
	 * don't terminate the operation.
	 *
	 * Therefore, for non-final requests, we use the DMA IRQ, which
	 * triggers when DMA has finishing feeding all the input data to the
	 * HCU, but the HCU may still be processing it. This is fine, since we
	 * will wait for the HCU processing to be completed when we try to read
	 * intermediate results, in ocs_hcu_get_intermediate_data().
	 */
    '''
    if finalize:
        ocs_hcu_done_irq_en(hcu_dev)
    else:
        ocs_hcu_dma_irq_en(hcu_dev)

    # reinit_completion

    writel(dma_list.dma_addr, hcu_dev.io_base + OCS_HCU_DMA_NEXT_SRC_DESCR)
    writel(0, hcu_dev.io_base + OCS_HCU_DMA_NEXT_SRC_DESCR + 4)
    writel(0, hcu_dev.io_base + OCS_HCU_DMA_SRC_SIZE)
    writel(0, hcu_dev.io_base + OCS_HCU_DMA_DST_SIZE)

    writel(OCS_HCU_START, hcu_dev.io_base + OCS_HCU_OPERATION)

    writel(cfg, hcu_dev.io_base + OCS_HCU_DMA_DMA_MODE)

    if finalize:
        writel(OCS_HCU_TERMINATE, hcu_dev.io_base + OCS_HCU_OPERATION)

    rc = ocs_hcu_wait_and_disable_irq(hcu_dev)
    if rc != 0:
        return rc

    return 0


def ocs_hcu_dma_list_alloc(hcu_dev,
                           max_nents, start_address = 0xF510b600):
    dma_list = ocs_hcu_dma_list()

   # LIST_RAM_ADDRESS = 0x800  # start address of array-list

   # HCU_LIST_DMA = hcu_dev.io_base + start_address    

    dma_list.dma_addr = start_address 

    dma_list.head = ocs_hcu_dma_entry()

    dma_list.max_nents = max_nents

    return dma_list


# Add a new DMA entry at the end of the OCS DMA list.
def ocs_hcu_dma_list_add_tail(hcu_dev,
                              dma_list,
                              addr, length):
    if length == 0:
        return 0

    if dma_list is None:
        return -EINVAL

    if addr & ~OCS_HCU_DMA_BIT_MASK:
        print("Unexpected error: Invalid DMA address for OCS HCU")
        return -EINVAL

    old_tail = dma_list.tail
    new_tail = None
    if old_tail is None:
        new_tail = dma_list.head
    else:
        new_tail = ocs_hcu_dma_entry()
        # new_tail = old_tail + 4 * 4  # sizeof(dma_entry): 4 * 4(bytes per field)

    # if new_tail - dma_list.head >= dma_list.max_nents:
    #   return -ENOMEM

    mask_32_bit = bit_mask(32)

    if not (old_tail is None):
        old_tail.ll_flags &= ~OCS_LL_DMA_FLAG_TERMINATE
        old_tail.ll_flags &= mask_32_bit

        old_tail.nxt_desc = dma_list.dma_addr + dma_list.size * 16

        # Rewrite old tail in dma
        write_dma_entry(old_tail, dma_list.dma_addr + 16 * (dma_list.size - 1))

    new_tail.src_addr = addr & mask_32_bit
    new_tail.src_len = length & mask_32_bit
    new_tail.ll_flags = OCS_LL_DMA_FLAG_TERMINATE
    new_tail.nxt_desc = 0

    # Put new tail
    write_dma_entry(new_tail, dma_list.dma_addr + dma_list.size * 16)

    # Update list tail with new tail.
    dma_list.tail = new_tail

    dma_list.size += 1
    return 0


'''
My implementation of dma_map_single
@hcu_dev - ocs hcu device
@data - bytearray of data
@data_len - len of @data
@attrs - attributes (not used)

Returns pointer to data array in memory of @hcu_dev device
'''


def dma_map_single(hcu_dev, data, data_len, attrs):
    # I don't know the truth offset,
    # but I borrow this one from https://github.com/peterbjornx/meloader/blob/master/periph/ocs/hash/hash.c
    data_offset = 0x600
    hcu_data_base_address = hcu_dev.io_base + data_offset
    block_size = 4
    blocks_num = data_len // block_size
    rest = data_len % block_size
    # data: data[0], data[1], data[2], data[3], ...
    # memory: data[0], data[1], data[2], data[3], ...
    for i in range(blocks_num):
        cur_address = hcu_data_base_address + block_size * i
        value_32_bit = data[i * block_size]  # 3 byte
        value_32_bit <<= 8
        value_32_bit |= data[i * block_size + 1]  # 2 byte
        value_32_bit <<= 8
        value_32_bit |= data[i * block_size + 2]  # 1 byte
        value_32_bit <<= 8
        value_32_bit |= data[i * block_size + 3]  # 0 byte

        writel(value_32_bit, cur_address)

    N = block_size * blocks_num
    for i in range(rest):
        cur_address = hcu_data_base_address + N + i
        writeb(data[N + i], cur_address)
    return hcu_data_base_address


def dma_map_data(hcu_dev, data, data_len, attrs):
    # Set data allocation memory offset
    HCU_DMA_INBUFFER_OFFSET = 0x600
    HCU_DATA_OFFSET = 0x50

    #Allocate data in memory
    #data_addr = alloc_bytes(data,data_len, hcu_dev.io_base + HCU_DMA_INBUFFER_OFFSET + HCU_DATA_OFFSET)
    
    
    # Create dma_list
    #dma_list = ocs_hcu_dma_list_alloc(hcu_dev, 10000) # stupid value for max_nents

    # Add dma_entry with data addresses
    #ocs_hcu_dma_list_add_tail(hcu_dev, dma_list, addr=data_addr, length=data_len)

    write_data_to_one_addr(hcu_dev.io_base + HCU_DMA_INBUFFER_OFFSET, data, data_len)
    
    return hcu_dev.io_base + HCU_DMA_INBUFFER_OFFSET


'''
Free be like function. Currently do nothing
'''


def dma_unmap_single(dev, dma_handle, data_len, attrs):
    HCU_INBUFFER_OFFSET = 0x600
    for i in range(data_len):
        iowrite8(0, dma_handle + i)
    return 0


'''
/**
 * ocs_hcu_hash_init() - Initialize hash operation context.
 * @ctx:	The context to initialize.
 * @algo:	The hashing algorithm to use.
 *
 * Return:	0 on success, negative error code otherwise.
 */
'''


def ocs_hcu_hash_init(ctx, algo):
    if ctx is None:
        return -EINVAL

    ctx.algo = algo
    ctx.idata.msg_len_lo = 0
    ctx.idata.msg_len_hi = 0
    # No need to set idata.digest to 0.

    return 0


'''
/**
 * ocs_hcu_hash_update() - Perform a hashing iteration.
 * @hcu_dev:	The OCS HCU device to use.
 * @ctx:	The OCS HCU hashing context.
 * @dma_list:	The OCS DMA list mapping the input data to process.
 *
 * Return: 0 on success; negative error code otherwise.
 */
'''


def ocs_hcu_hash_update(hcu_dev,
                        ctx,
                        dma_list):
    if hcu_dev is None or ctx is None:
        return -EINVAL

    # Configure the hardware for the current request.
    rc = ocs_hcu_hw_cfg(hcu_dev, ctx.algo, False)
    if rc:
        return rc

    # If we already processed some data, idata needs to be set.
    if ctx.idata.msg_len_lo != 0 or ctx.idata.msg_len_hi != 0:
        ocs_hcu_set_intermediate_data(hcu_dev, ctx.idata, ctx.algo)

    # Start linked - list DMA hashing.
    rc = ocs_hcu_ll_dma_start(hcu_dev, dma_list, False)
    if rc != 0:
        return rc

    # Update idata and return.
    return ocs_hcu_get_intermediate_data(hcu_dev, ctx.idata, ctx.algo)


'''
/**
 * ocs_hcu_hash_finup() - Update and finalize hash computation.
 * @hcu_dev:	The OCS HCU device to use.
 * @ctx:	The OCS HCU hashing context.
 * @dma_list:	The OCS DMA list mapping the input data to process.
 * @dgst:	The buffer where to save the computed digest.
 * @dgst_len:	The length of @dgst.
 *
 * Return: 0 on success; negative error code otherwise.
 */
'''


def ocs_hcu_hash_finup(hcu_dev,
                       ctx,
                       dma_list,
                       dgst, dgst_len):
    if hcu_dev is None or ctx is None:
        return -EINVAL

    # Configure the hardware for the current request.
    rc = ocs_hcu_hw_cfg(hcu_dev, ctx.algo, False)
    if rc != 0:
        return rc

    # If we already processed some data, idata needs to be set.
    if ctx.idata.msg_len_lo != 0 or ctx.idata.msg_len_hi != 0:
        ocs_hcu_set_intermediate_data(hcu_dev, ctx.idata, ctx.algo)

    # Start linked - list DMA hashing.
    rc = ocs_hcu_ll_dma_start(hcu_dev, dma_list, True)
    if rc != 0:
        return rc

    # Get digest and return.
    return ocs_hcu_get_digest(hcu_dev, ctx.algo, dgst, dgst_len)


'''
/**
 * ocs_hcu_hash_final() - Finalize hash computation.
 * @hcu_dev:		The OCS HCU device to use.
 * @ctx:		The OCS HCU hashing context.
 * @dgst:		The buffer where to save the computed digest.
 * @dgst_len:		The length of @dgst.
 *
 * Return: 0 on success; negative error code otherwise.
 */
'''


def ocs_hcu_hash_final(hcu_dev,
                       ctx, dgst,
                       dgst_len):
    if hcu_dev is None or ctx is None:
        return -EINVAL

    # Configure the hardware for the current request.
    rc = ocs_hcu_hw_cfg(hcu_dev, ctx.algo, False)
    if rc:
        return rc
    # If we already processed some data, idata needs to be set.
    if ctx.idata.msg_len_lo != 0 or ctx.idata.msg_len_hi != 0:
        ocs_hcu_set_intermediate_data(hcu_dev, ctx.idata, ctx.algo)

    # Enable HCU interrupts, so that HCU_DONE will be triggered once the *final hash is computed.
    ocs_hcu_done_irq_en(hcu_dev)
    # reinit_completion( & hcu_dev->irq_done);
    writel(OCS_HCU_TERMINATE, hcu_dev.io_base + OCS_HCU_OPERATION)

    rc = ocs_hcu_wait_and_disable_irq(hcu_dev)
    if rc != 0:
        return rc

    # Get digest and return.
    return ocs_hcu_get_digest(hcu_dev, ctx.algo, dgst, dgst_len)


'''
/**
 * ocs_hcu_digest() - Compute hash digest.
 * @hcu_dev:		The OCS HCU device to use.
 * @algo:		The hash algorithm to use.
 * @data:		The input data to process.
 * @data_len:		The length of @data.
 * @dgst:		The buffer where to save the computed digest.
 * @dgst_len:		The length of @dgst.
 *
 * Return: 0 on success; negative error code otherwise.
 */
'''


def ocs_hcu_digest(hcu_dev, algo,
                   data, data_len, dgst, dgst_len):
    dev = hcu_dev.dev

    # *Configure the hardware for the current request.
    rc = ocs_hcu_hw_cfg(hcu_dev, algo, False)
    if rc != 0:
        return rc

    dma_handle = dma_map_data(hcu_dev, data, data_len, DMA_TO_DEVICE)  # create pointer to data.
    # if dma_mapping_error(dev, dma_handle):
    #    return -EIO

    reg = HCU_DMA_SNOOP_MASK | HCU_DMA_EN

    ocs_hcu_done_irq_en(hcu_dev)

    # reinit_completion( & hcu_dev->irq_done);

    writel(dma_handle, hcu_dev.io_base + OCS_HCU_DMA_SRC_ADDR)
    writel(data_len, hcu_dev.io_base + OCS_HCU_DMA_SRC_SIZE)
    writel(OCS_HCU_START, hcu_dev.io_base + OCS_HCU_OPERATION)
    writel(reg, hcu_dev.io_base + OCS_HCU_DMA_DMA_MODE)

    writel(OCS_HCU_TERMINATE, hcu_dev.io_base + OCS_HCU_OPERATION)

    rc = ocs_hcu_wait_and_disable_irq(hcu_dev)
    if rc != 0:
        return rc

    dma_unmap_single(dev, dma_handle, data_len, DMA_TO_DEVICE)

    return ocs_hcu_get_digest(hcu_dev, algo, dgst, dgst_len)


'''
/**
 * ocs_hcu_hmac() - Compute HMAC.
 * @hcu_dev:		The OCS HCU device to use.
 * @algo:		The hash algorithm to use with HMAC.
 * @key:		The key to use.
 * @dma_list:	The OCS DMA list mapping the input data to process.
 * @key_len:		The length of @key.
 * @dgst:		The buffer where to save the computed HMAC.
 * @dgst_len:		The length of @dgst.
 *
 * Return: 0 on success; negative error code otherwise.
 */
'''


def ocs_hcu_hmac(hcu_dev, algo,
                 key, key_len,
                 dma_list,
                 dgst,
                 dgst_len):
    # Ensure 'key' is not NULL.
    if key is None or key_len == 0:
        return -EINVAL

    # Configure the hardware for the current request.
    rc = ocs_hcu_hw_cfg(hcu_dev, algo, True)
    if rc != 0:
        return rc

    rc = ocs_hcu_write_key(hcu_dev, key, key_len)
    if rc != 0:
        return rc

    rc = ocs_hcu_ll_dma_start(hcu_dev, dma_list, True)

    # Clear HW key before processing return code.
    ocs_hcu_clear_key(hcu_dev)

    if rc != 0:
        return rc

    return ocs_hcu_get_digest(hcu_dev, algo, dgst, dgst_len)

def ocs_hcu_irq_handler(irq, hcu_dev, irq_pair=None):
    # Read and clear the HCU interrupt.
    hcu_irq = readl(hcu_dev.io_base + OCS_HCU_ISR)
    writel(hcu_irq, hcu_dev.io_base + OCS_HCU_ISR)

    # Read and clear the HCU DMA interrupt.
    dma_irq = readl(hcu_dev.io_base + OCS_HCU_DMA_MSI_ISR)
    writel(dma_irq, hcu_dev.io_base + OCS_HCU_DMA_MSI_ISR)

    if not (irq_pair is None):
        irq_pair = (hcu_irq, dma_irq)

    # Check for errors.
    if hcu_irq & HCU_IRQ_HASH_ERR_MASK or dma_irq & HCU_DMA_IRQ_ERR_MASK:
        hcu_dev.irq_err = True
        return IRQ_HANDLED

    # Check for DONE IRQs.
    if hcu_irq & HCU_IRQ_HASH_DONE or dma_irq & HCU_DMA_IRQ_SRC_DONE:
        return IRQ_HANDLED

    return IRQ_NONE

def print_dma_errors(dma_irq):
    if dma_irq & HCU_DMA_IRQ_SAI_ERR:
        print("Error: SAI ERROR")
    if dma_irq & HCU_DMA_IRQ_BAD_COMP_ERR:
        print("Error: BAD COMP ERROR")
    if dma_irq & HCU_DMA_IRQ_INBUF_RD_ERR:
        print("Error: INBUF READ ERROR")
    if dma_irq & HCU_DMA_IRQ_INBUF_WD_ERR:
        print("Error: INBUF WD ERROR")
    if dma_irq & HCU_DMA_IRQ_OUTBUF_WR_ERR:
        print("Error: OUTBUF WRITE ERROR")
    if dma_irq & HCU_DMA_IRQ_OUTBUF_RD_ERR:
        print("Error: OUTBUF READ ERROR")
    if dma_irq & HCU_DMA_IRQ_CRD_ERR:
        print("Error: CRD ERROR")

