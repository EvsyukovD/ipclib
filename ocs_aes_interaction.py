from ocs_aes_classes import *
from dev_common import *

AES_COMMAND_OFFSET = 0x0000
AES_KEY_0_OFFSET = 0x0004
AES_KEY_1_OFFSET = 0x0008
AES_KEY_2_OFFSET = 0x000C
AES_KEY_3_OFFSET = 0x0010
AES_KEY_4_OFFSET = 0x0014
AES_KEY_5_OFFSET = 0x0018
AES_KEY_6_OFFSET = 0x001C
AES_KEY_7_OFFSET = 0x0020
AES_IV_0_OFFSET = 0x0024
AES_IV_1_OFFSET = 0x0028
AES_IV_2_OFFSET = 0x002C
AES_IV_3_OFFSET = 0x0030
AES_ACTIVE_OFFSET = 0x0034
AES_STATUS_OFFSET = 0x0038
AES_KEY_SIZE_OFFSET = 0x0044
AES_IER_OFFSET = 0x0048
AES_ISR_OFFSET = 0x005C
AES_MULTIPURPOSE1_0_OFFSET = 0x0200
AES_MULTIPURPOSE1_1_OFFSET = 0x0204
AES_MULTIPURPOSE1_2_OFFSET = 0x0208
AES_MULTIPURPOSE1_3_OFFSET = 0x020C
AES_MULTIPURPOSE2_0_OFFSET = 0x0220
AES_MULTIPURPOSE2_1_OFFSET = 0x0224
AES_MULTIPURPOSE2_2_OFFSET = 0x0228
AES_MULTIPURPOSE2_3_OFFSET = 0x022C
AES_BYTE_ORDER_CFG_OFFSET = 0x02C0
AES_TLEN_OFFSET = 0x0300
AES_T_MAC_0_OFFSET = 0x0304
AES_T_MAC_1_OFFSET = 0x0308
AES_T_MAC_2_OFFSET = 0x030C
AES_T_MAC_3_OFFSET = 0x0310
AES_PLEN_OFFSET = 0x0314
AES_A_DMA_SRC_ADDR_OFFSET = 0x0400
AES_A_DMA_DST_ADDR_OFFSET = 0x0404
AES_A_DMA_SRC_SIZE_OFFSET = 0x0408
AES_A_DMA_DST_SIZE_OFFSET = 0x040C
AES_A_DMA_DMA_MODE_OFFSET = 0x0410
AES_A_DMA_NEXT_SRC_DESCR_OFFSET = 0x0418
AES_A_DMA_NEXT_DST_DESCR_OFFSET = 0x041C
AES_A_DMA_WHILE_ACTIVE_MODE_OFFSET = 0x0420
AES_A_DMA_LOG_OFFSET = 0x0424
AES_A_DMA_STATUS_OFFSET = 0x0428
AES_A_DMA_PERF_CNTR_OFFSET = 0x042C
AES_A_DMA_MSI_ISR_OFFSET = 0x0480
AES_A_DMA_MSI_IER_OFFSET = 0x0484
AES_A_DMA_MSI_MASK_OFFSET = 0x0488
AES_A_DMA_INBUFFER_WRITE_FIFO_OFFSET = 0x0600
AES_A_DMA_OUTBUFFER_READ_FIFO_OFFSET = 0x0700

'''
/*
 * AES_A_DMA_DMA_MODE register.
 * Default: 0x00000000.
 * bit[31]	ACTIVE
 *		This bit activates the DMA. When the DMA finishes, it resets
 *		this bit to zero.
 * bit[30:26]	Unused by this driver.
 * bit[25]	SRC_LINK_LIST_EN
 *		Source link list enable bit. When the linked list is terminated
 *		this bit is reset by the DMA.
 * bit[24]	DST_LINK_LIST_EN
 *		Destination link list enable bit. When the linked list is
 *		terminated this bit is reset by the DMA.
 * bit[23:0]	Unused by this driver.
 */
'''

AES_A_DMA_DMA_MODE_ACTIVE = bit(31)
AES_A_DMA_DMA_MODE_SRC_LINK_LIST_EN = bit(25)
AES_A_DMA_DMA_MODE_DST_LINK_LIST_EN = bit(24)

'''
/*
 * AES_ACTIVE register
 * default 0x00000000
 * bit[31:10]	Reserved
 * bit[9]	LAST_ADATA
 * bit[8]	LAST_GCX
 * bit[7:2]	Reserved
 * bit[1]	TERMINATION
 * bit[0]	TRIGGER
 */
'''

AES_ACTIVE_LAST_ADATA = bit(9)
AES_ACTIVE_LAST_CCM_GCM = bit(8)
AES_ACTIVE_TERMINATION = bit(1)
AES_ACTIVE_TRIGGER = bit(0)

AES_DISABLE_INT = 0x00000000
AES_DMA_CPD_ERR_INT = bit(8)
AES_DMA_OUTBUF_RD_ERR_INT = bit(7)
AES_DMA_OUTBUF_WR_ERR_INT = bit(6)
AES_DMA_INBUF_RD_ERR_INT = bit(5)
AES_DMA_INBUF_WR_ERR_INT = bit(4)
AES_DMA_BAD_COMP_INT = bit(3)
AES_DMA_SAI_INT = bit(2)
AES_DMA_SRC_DONE_INT = bit(0)
AES_COMPLETE_INT = bit(1)

AES_DMA_MSI_MASK_CLEAR = bit(0)

AES_128_BIT_KEY = 0x00000000
AES_256_BIT_KEY = bit(0)

AES_DEACTIVATE_PERF_CNTR = 0x00000000
AES_ACTIVATE_PERF_CNTR = bit(0)

AES_MAX_TAG_SIZE_U32 = 4

OCS_LL_DMA_FLAG_TERMINATE = bit(31)

'''
/*
 * There is an inconsistency in the documentation. This is documented as a
 * 11-bit value, but it is actually 10-bits.
 */
'''
AES_DMA_STATUS_INPUT_BUFFER_OCCUPANCY_MASK = 0x3FF

'''
/*
 * During CCM decrypt, the OCS block needs to finish processing the ciphertext
 * before the tag is written. For 128-bit mode this required delay is 28 OCS
 * clock cycles. For 256-bit mode it is 36 OCS clock cycles.
 */
'''

CCM_DECRYPT_DELAY_TAG_CLK_COUNT = 36

'''
/*
 * During CCM decrypt there must be a delay of at least 42 OCS clock cycles
 * between setting the TRIGGER bit in AES_ACTIVE and setting the LAST_CCM_GCM
 * bit in the same register (as stated in the OCS databook)
 */
'''

CCM_DECRYPT_DELAY_LAST_GCX_CLK_COUNT = 42

# See RFC3610 section 2.2

L_PRIME_MIN = 1
L_PRIME_MAX = 7

'''
/*
 * CCM IV format from RFC 3610 section 2.3
 *
 *   Octet Number   Contents
 *   ------------   ---------
 *   0              Flags
 *   1 ... 15-L     Nonce N
 *   16-L ... 15    Counter i
 *
 * Flags = L' = L - 1
 */
'''

L_PRIME_IDX = 0
COUNTER_START = lambda lprime: (16 - ((lprime) + 1))
COUNTER_LEN = lambda lprime: ((lprime) + 1)


class aes_counter_mode(object):
    AES_CTR_M_NO_INC = 0,
    AES_CTR_M_32_INC = 1,
    AES_CTR_M_64_INC = 2,
    AES_CTR_M_128_INC = 3


'''
/**
 * struct ocs_dma_linked_list - OCS DMA linked list entry.
 * @src_addr:   Source address of the data.
 * @src_len:    Length of data to be fetched.
 * @next:	Next dma_list to fetch.
 * @ll_flags:   Flags (Freeze @ terminate) for the DMA engine.
 */
'''


class ocs_dma_linked_list(object):
    def __init__(self):
        self.src_addr = 0
        self.src_len = 0
        self.next = 0
        self.ll_flags = 0


'''
/*
 * Set endianness of inputs and outputs
 * AES_BYTE_ORDER_CFG
 * default 0x00000000
 * bit [10] - KEY_HI_LO_SWAP
 * bit [9] - KEY_HI_SWAP_DWORDS_IN_OCTWORD
 * bit [8] - KEY_HI_SWAP_BYTES_IN_DWORD
 * bit [7] - KEY_LO_SWAP_DWORDS_IN_OCTWORD
 * bit [6] - KEY_LO_SWAP_BYTES_IN_DWORD
 * bit [5] - IV_SWAP_DWORDS_IN_OCTWORD
 * bit [4] - IV_SWAP_BYTES_IN_DWORD
 * bit [3] - DOUT_SWAP_DWORDS_IN_OCTWORD
 * bit [2] - DOUT_SWAP_BYTES_IN_DWORD
 * bit [1] - DOUT_SWAP_DWORDS_IN_OCTWORD
 * bit [0] - DOUT_SWAP_BYTES_IN_DWORD
 */
'''


def aes_a_set_endianness(aes_dev):
    iowrite32(0x7FF, aes_dev.base_reg + AES_BYTE_ORDER_CFG_OFFSET)


#  Trigger AES process start.
def aes_a_op_trigger(aes_dev):
    iowrite32(AES_ACTIVE_TRIGGER, aes_dev.base_reg + AES_ACTIVE_OFFSET)


# Indicate last bulk of data.

def aes_a_op_termination(aes_dev):
    iowrite32(AES_ACTIVE_TERMINATION, aes_dev.base_reg + AES_ACTIVE_OFFSET)


'''
/*
 * Set LAST_CCM_GCM in AES_ACTIVE register and clear all other bits.
 *
 * Called when DMA is programmed to fetch the last batch of data.
 * - For AES-CCM it is called for the last batch of Payload data and Ciphertext
 *   data.
 * - For AES-GCM, it is called for the last batch of Plaintext data and
 *   Ciphertext data.
 */
'''


def aes_a_set_last_gcx(aes_dev):
    iowrite32(AES_ACTIVE_LAST_CCM_GCM,
              aes_dev.base_reg + AES_ACTIVE_OFFSET)


# Wait for LAST_CCM_GCM bit to be unset.

def aes_a_wait_last_gcx(aes_dev):
    aes_active_reg = ioread32(aes_dev.base_reg + AES_ACTIVE_OFFSET)

    while aes_active_reg & AES_ACTIVE_LAST_CCM_GCM:
        aes_active_reg = ioread32(aes_dev.base_reg + AES_ACTIVE_OFFSET)


# Wait for 10 bits of input occupancy.

def aes_a_dma_wait_input_buffer_occupancy(aes_dev):
    reg = ioread32(aes_dev.base_reg + AES_A_DMA_STATUS_OFFSET)
    while reg & AES_DMA_STATUS_INPUT_BUFFER_OCCUPANCY_MASK:
        reg = ioread32(aes_dev.base_reg + AES_A_DMA_STATUS_OFFSET)


'''
/*
  * Set LAST_CCM_GCM and LAST_ADATA bits in AES_ACTIVE register (and clear all
  * other bits).
  *
  * Called when DMA is programmed to fetch the last batch of Associated Data
  * (CCM case) or Additional Authenticated Data (GCM case).
  */
'''


def aes_a_set_last_gcx_and_adata(aes_dev):
    iowrite32(AES_ACTIVE_LAST_ADATA | AES_ACTIVE_LAST_CCM_GCM,
              aes_dev.base_reg + AES_ACTIVE_OFFSET)


# Set DMA src and dst transfer size to 0

def aes_a_dma_set_xfer_size_zero(aes_dev):
    iowrite32(0, aes_dev.base_reg + AES_A_DMA_SRC_SIZE_OFFSET)
    iowrite32(0, aes_dev.base_reg + AES_A_DMA_DST_SIZE_OFFSET)


# Activate DMA for zero-byte transfer case.

def aes_a_dma_active(aes_dev):
    iowrite32(AES_A_DMA_DMA_MODE_ACTIVE,
              aes_dev.base_reg + AES_A_DMA_DMA_MODE_OFFSET)


# Activate DMA and enable src linked list

def aes_a_dma_active_src_ll_en(aes_dev):
    iowrite32(AES_A_DMA_DMA_MODE_ACTIVE |
              AES_A_DMA_DMA_MODE_SRC_LINK_LIST_EN,
              aes_dev.base_reg + AES_A_DMA_DMA_MODE_OFFSET)


# Activate DMA and enable dst linked list
def aes_a_dma_active_dst_ll_en(aes_dev):
    iowrite32(AES_A_DMA_DMA_MODE_ACTIVE |
              AES_A_DMA_DMA_MODE_DST_LINK_LIST_EN,
              aes_dev.base_reg + AES_A_DMA_DMA_MODE_OFFSET)


# Activate DMA and enable src and dst linked lists
def aes_a_dma_active_src_dst_ll_en(aes_dev):
    iowrite32(AES_A_DMA_DMA_MODE_ACTIVE |
              AES_A_DMA_DMA_MODE_SRC_LINK_LIST_EN |
              AES_A_DMA_DMA_MODE_DST_LINK_LIST_EN,
              aes_dev.base_reg + AES_A_DMA_DMA_MODE_OFFSET)


# Reset PERF_CNTR to 0 and activate it

def aes_a_dma_reset_and_activate_perf_cntr(aes_dev):
    iowrite32(0x00000000, aes_dev.base_reg + AES_A_DMA_PERF_CNTR_OFFSET)
    iowrite32(AES_ACTIVATE_PERF_CNTR,
              aes_dev.base_reg + AES_A_DMA_WHILE_ACTIVE_MODE_OFFSET)


# Wait until PERF_CNTR is > delay, then deactivate it
def aes_a_dma_wait_and_deactivate_perf_cntr(aes_dev,
                                            delay):
    while ioread32(aes_dev.base_reg + AES_A_DMA_PERF_CNTR_OFFSET) < delay:
        iowrite32(AES_DEACTIVATE_PERF_CNTR,
                  aes_dev.base_reg + AES_A_DMA_WHILE_ACTIVE_MODE_OFFSET)


# Disable AES and DMA IRQ.
def aes_irq_disable(aes_dev):
    # Disable interrupts
    iowrite32(AES_DISABLE_INT,
              aes_dev.base_reg + AES_A_DMA_MSI_IER_OFFSET)
    iowrite32(AES_DISABLE_INT, aes_dev.base_reg + AES_IER_OFFSET)

    # Clear any pending interrupt
    isr_val = ioread32(aes_dev.base_reg + AES_A_DMA_MSI_ISR_OFFSET)
    if isr_val:
        iowrite32(isr_val,
                  aes_dev.base_reg + AES_A_DMA_MSI_ISR_OFFSET)

    isr_val = ioread32(aes_dev.base_reg + AES_A_DMA_MSI_MASK_OFFSET)
    if isr_val:
        iowrite32(isr_val,
                  aes_dev.base_reg + AES_A_DMA_MSI_MASK_OFFSET)

    isr_val = ioread32(aes_dev.base_reg + AES_ISR_OFFSET)
    if isr_val:
        iowrite32(isr_val, aes_dev.base_reg + AES_ISR_OFFSET)


# Enable AES or DMA IRQ.  IRQ is disabled once fired.
def aes_irq_enable(aes_dev, irq):
    if irq == AES_COMPLETE_INT:
        # Ensure DMA error interrupts are enabled
        iowrite32(AES_DMA_CPD_ERR_INT |
                  AES_DMA_OUTBUF_RD_ERR_INT |
                  AES_DMA_OUTBUF_WR_ERR_INT |
                  AES_DMA_INBUF_RD_ERR_INT |
                  AES_DMA_INBUF_WR_ERR_INT |
                  AES_DMA_BAD_COMP_INT |
                  AES_DMA_SAI_INT,
                  aes_dev.base_reg + AES_A_DMA_MSI_IER_OFFSET)
        # /*
        # * AES_IER
        # * default 0x00000000
        # * bits [31:3] - reserved
        # * bit [2] - EN_SKS_ERR
        # * bit [1] - EN_AES_COMPLETE
        # * bit [0] - reserved
        # */
        iowrite32(AES_COMPLETE_INT, aes_dev.base_reg + AES_IER_OFFSET)
        return

    if irq == AES_DMA_SRC_DONE_INT:
        # Ensure AES interrupts are disabled
        iowrite32(AES_DISABLE_INT, aes_dev.base_reg + AES_IER_OFFSET)
        # /*
        # * DMA_MSI_IER
        # * default 0x00000000
        # * bits [31:9] - reserved
        # * bit [8] - CPD_ERR_INT_EN
        # * bit [7] - OUTBUF_RD_ERR_INT_EN
        # * bit [6] - OUTBUF_WR_ERR_INT_EN
        # * bit [5] - INBUF_RD_ERR_INT_EN
        # * bit [4] - INBUF_WR_ERR_INT_EN
        # * bit [3] - BAD_COMP_INT_EN
        # * bit [2] - SAI_INT_EN
        # * bit [1] - DST_DONE_INT_EN
        # * bit [0] - SRC_DONE_INT_EN
        # */
        iowrite32(AES_DMA_CPD_ERR_INT |
                  AES_DMA_OUTBUF_RD_ERR_INT |
                  AES_DMA_OUTBUF_WR_ERR_INT |
                  AES_DMA_INBUF_RD_ERR_INT |
                  AES_DMA_INBUF_WR_ERR_INT |
                  AES_DMA_BAD_COMP_INT |
                  AES_DMA_SAI_INT |
                  AES_DMA_SRC_DONE_INT,
                  aes_dev.base_reg + AES_A_DMA_MSI_IER_OFFSET)


# Enable and wait for IRQ (either from OCS AES engine or DMA)
def ocs_aes_irq_enable_and_wait(aes_dev, irq):
    # reinit_completion(&aes_dev->irq_completion)
    aes_irq_enable(aes_dev, irq)
    # rc = wait_for_completion_interruptible(&aes_dev->irq_completion);
    # if rc != 0:
    #	return rc
    if aes_dev.dma_err_mask != 0:
        return -EIO
    else:
        return 0


# Configure DMA to OCS, linked list mode
def dma_to_ocs_aes_ll(aes_dev,
                      dma_list):
    iowrite32(0, aes_dev.base_reg + AES_A_DMA_SRC_SIZE_OFFSET)
    iowrite32(dma_list,
              aes_dev.base_reg + AES_A_DMA_NEXT_SRC_DESCR_OFFSET)


# Configure DMA from OCS, linked list mode
def dma_from_ocs_aes_ll(aes_dev,
                        dma_list):
    iowrite32(0, aes_dev.base_reg + AES_A_DMA_DST_SIZE_OFFSET)
    iowrite32(dma_list,
              aes_dev.base_reg + AES_A_DMA_NEXT_DST_DESCR_OFFSET)


def ocs_aes_irq_handler(irq, dev_id):
    aes_dev = dev_id

    # Read DMA ISR status.
    aes_dma_isr = ioread32(aes_dev.base_reg + AES_A_DMA_MSI_ISR_OFFSET);

    # Disable and clear interrupts.
    aes_irq_disable(aes_dev)

    # Save DMA error status.
    aes_dev.dma_err_mask = aes_dma_isr & (AES_DMA_CPD_ERR_INT |
                                          AES_DMA_OUTBUF_RD_ERR_INT |
                                          AES_DMA_OUTBUF_WR_ERR_INT |
                                          AES_DMA_INBUF_RD_ERR_INT |
                                          AES_DMA_INBUF_WR_ERR_INT |
                                          AES_DMA_BAD_COMP_INT |
                                          AES_DMA_SAI_INT)

    # Signal IRQ completion.
    # complete(&aes_dev->irq_completion)

    return IRQ_HANDLED


'''
/**
 * ocs_aes_set_key() - Write key into OCS AES hardware.
 * @aes_dev:	The OCS AES device to write the key to.
 * @key_size:	The size of the key (in bytes).
 * @key:	The key to write.
 * @cipher:	The cipher the key is for.
 *
 * For AES @key_size must be either 16 or 32. For SM4 @key_size must be 16.
 *
 * Return:	0 on success, negative error code otherwise.
 */
'''


def ocs_aes_set_key(aes_dev, key_size, key,
                    cipher):
    # OCS AES supports 128 - bit and 256 - bit keys only.
    if cipher == ocs_cipher.OCS_AES and not (key_size == 32 or key_size == 16):
        # dev_err(aes_dev->dev,"%d-bit keys not supported by AES cipher\n", key_size * 8);
        print("%d-bit keys not supported by AES cipher" % key_size * 8)
        return -EINVAL

    # OCS SM4 supports 128 - bit keys only.
    if cipher == ocs_cipher.OCS_SM4 and key_size != 16:
        # dev_err(aes_dev->dev,"%d-bit keys not supported for SM4 cipher\n", key_size * 8);
        print("%d-bit keys not supported by SM4 cipher" % key_size * 8)
        return -EINVAL

    if key is None:
        return -EINVAL

    block_size = 4
    n = key_size // block_size  # key_size // sizeof(u32)
    # Write key to AES_KEY[0 - 7] registers
    for i in range(n):
        value_32_bit = 0
        value_32_bit |= key[i * block_size]  # 3 byte
        value_32_bit <<= 8
        value_32_bit |= key[i * block_size + 1]  # 2 byte
        value_32_bit <<= 8
        value_32_bit |= key[i * block_size + 2]  # 1 byte
        value_32_bit <<= 8
        value_32_bit |= key[i * block_size + 3]  # 0 byte

        iowrite32(value_32_bit, aes_dev.base_reg + AES_KEY_0_OFFSET + i * block_size)

    # /*
    # * Write key size
    # * bits [31:1] - reserved
    # * bit [0] - AES_KEY_SIZE
    # *           0 - 128 bit key
    # *           1 - 256 bit key
    # */
    val = AES_128_BIT_KEY
    if key_size != 16:
        val = AES_256_BIT_KEY

    iowrite32(val, aes_dev.base_reg + AES_KEY_SIZE_OFFSET)

    return 0


# Write AES_COMMAND
'''
/* AES_COMMAND
	 * default 0x000000CC
	 * bit [14] - CIPHER_SELECT
	 *            0 - AES
	 *            1 - SM4
	 * bits [11:8] - OCS_AES_MODE
	 *               0000 - ECB
	 *               0001 - CBC
	 *               0010 - CTR
	 *               0110 - CCM
	 *               0111 - GCM
	 *               1001 - CTS
	 * bits [7:6] - AES_INSTRUCTION
	 *              00 - ENCRYPT
	 *              01 - DECRYPT
	 *              10 - EXPAND
	 *              11 - BYPASS
	 * bits [3:2] - CTR_M_BITS
	 *              00 - No increment
	 *              01 - Least significant 32 bits are incremented
	 *              10 - Least significant 64 bits are incremented
	 *              11 - Full 128 bits are incremented
	 */
'''


def set_ocs_aes_command(aes_dev,
                        cipher,
                        mode,
                        instruction):
    val = (cipher << 14) | (mode << 8) | (instruction << 6) | (aes_counter_mode.AES_CTR_M_128_INC << 2)
    iowrite32(val, aes_dev.base_reg + AES_COMMAND_OFFSET)


def ocs_aes_init(aes_dev,
                 mode,
                 cipher,
                 instruction):
    # Ensure interrupts are disabled and pending interrupts cleared. * /
    aes_irq_disable(aes_dev)

    # Set endianness recommended by data - sheet.
    aes_a_set_endianness(aes_dev)

    # Set AES_COMMAND register.
    set_ocs_aes_command(aes_dev, cipher, mode, instruction)


'''
/*
 * Write the byte length of the last AES/SM4 block of Payload data (without
 * zero padding and without the length of the MAC) in register AES_PLEN.
 */
'''


def ocs_aes_write_last_data_blk_len(aes_dev,
                                    size):
    if size == 0:
        val = 0
        iowrite32(val, aes_dev.base_reg + AES_PLEN_OFFSET)
        return

    val = size % AES_BLOCK_SIZE
    if val == 0:
        val = AES_BLOCK_SIZE

    iowrite32(val, aes_dev.base_reg + AES_PLEN_OFFSET)


'''
/*
 * Validate inputs according to mode.
 * If OK return 0; else return -EINVAL.
 */
'''


def ocs_aes_validate_inputs(src_dma_list, src_size,
                            iv, iv_size,
                            aad_dma_list, aad_size,
                            tag, tag_size,
                            cipher, mode,
                            instruction,
                            dst_dma_list):
    # Ensure cipher, mode and instruction are valid.
    if not (cipher == ocs_cipher.OCS_AES or cipher == ocs_cipher.OCS_SM4):
        return -EINVAL

    if (mode != ocs_mode.OCS_MODE_ECB and mode != ocs_mode.OCS_MODE_CBC and
            mode != ocs_mode.OCS_MODE_CTR and mode != ocs_mode.OCS_MODE_CCM and
            mode != ocs_mode.OCS_MODE_GCM and mode != ocs_mode.OCS_MODE_CTS):
        return -EINVAL

    if (instruction != ocs_instruction.OCS_ENCRYPT and instruction != ocs_instruction.OCS_DECRYPT and
            instruction != ocs_instruction.OCS_EXPAND and instruction != ocs_instruction.OCS_BYPASS):
        return -EINVAL

    '''
    /*
	 * When instruction is OCS_BYPASS, OCS simply copies data from source
	 * to destination using DMA.
	 *
	 * AES mode is irrelevant, but both source and destination DMA
	 * linked-list must be defined.
	 */
    '''
    if instruction == ocs_instruction.OCS_BYPASS:
        if src_dma_list == DMA_MAPPING_ERROR or dst_dma_list == DMA_MAPPING_ERROR:
            return -EINVAL
        return 0

    '''
    /*
	 * For performance reasons switch based on mode to limit unnecessary
	 * conditionals for each mode
	 */
    '''

    if mode == ocs_mode.OCS_MODE_ECB:
        # Ensure input length is multiple of block size
        if src_size % AES_BLOCK_SIZE != 0:
            return -EINVAL

        # Ensure source and destination linked lists are created
        if src_dma_list == DMA_MAPPING_ERROR or dst_dma_list == DMA_MAPPING_ERROR:
            return -EINVAL

        return 0
    if mode == ocs_mode.OCS_MODE_CBC:
        # Ensure input length is multiple of block size
        if src_size % AES_BLOCK_SIZE != 0:
            return -EINVAL

        # Ensure source and destination linked lists are created
        if src_dma_list == DMA_MAPPING_ERROR or dst_dma_list == DMA_MAPPING_ERROR:
            return -EINVAL

        # Ensure IV is present and block size in length
        if iv is None or iv_size != AES_BLOCK_SIZE:
            return -EINVAL

        return 0
    if mode == ocs_mode.OCS_MODE_CTR:
        # Ensure input length of 1 byte or greater
        if src_size == 0:
            return -EINVAL
        # Ensure source and destination linked lists are created
        if src_dma_list == DMA_MAPPING_ERROR or dst_dma_list == DMA_MAPPING_ERROR:
            return -EINVAL

        # Ensure IV is present and block size in length
        if iv is None or iv_size != AES_BLOCK_SIZE:
            return -EINVAL

        return 0

    if mode == ocs_mode.OCS_MODE_CTS:
        # Ensure input length >= block size
        if src_size < AES_BLOCK_SIZE:
            return -EINVAL
        # Ensure source and destination linked lists are created
        if src_dma_list == DMA_MAPPING_ERROR or dst_dma_list == DMA_MAPPING_ERROR:
            return -EINVAL

        # Ensure IV is present and block size in length
        if iv is None or iv_size != AES_BLOCK_SIZE:
            return -EINVAL

        return 0

    if mode == ocs_mode.OCS_MODE_GCM:
        # Ensure IV is present and GCM_AES_IV_SIZE in length
        if iv is None or iv_size != GCM_AES_IV_SIZE:
            return -EINVAL

        # If input data present ensure source and destination linked *lists are created
        if (src_size != 0 and (src_dma_list == DMA_MAPPING_ERROR or
                               dst_dma_list == DMA_MAPPING_ERROR)):
            return -EINVAL

        # If aad present ensure aad linked list is created
        if aad_size != 0 and aad_dma_list == DMA_MAPPING_ERROR:
            return -EINVAL

        # Ensure tag destination is set
        if tag is None:
            return -EINVAL

        # Just ensure that tag_size doesn't cause overflows.
        if tag_size > (AES_MAX_TAG_SIZE_U32 * 4):
            return -EINVAL

        return 0

    if mode == ocs_mode.OCS_MODE_CCM:
        # Ensure IV is present and block size in length
        if iv is None or iv_size != AES_BLOCK_SIZE:
            return -EINVAL

        # 2 <= L <= 8, so 1 <= L' <= 7
        if iv[L_PRIME_IDX] < L_PRIME_MIN or iv[L_PRIME_IDX] > L_PRIME_MAX:
            return -EINVAL

        # If aad present ensure aad linked list is created
        if aad_size and aad_dma_list == DMA_MAPPING_ERROR:
            return -EINVAL

        # Just ensure that tag_size doesn't cause overflows.
        if tag_size > (AES_MAX_TAG_SIZE_U32 * 4):
            return -EINVAL

        if instruction == ocs_instruction.OCS_DECRYPT:
            if src_size and (src_dma_list == DMA_MAPPING_ERROR or dst_dma_list == DMA_MAPPING_ERROR):
                return -EINVAL

            # Ensure input tag is present
            if tag is None:
                return -EINVAL

            return 0

        # Instruction == OCS_ENCRYPT
        # Destination linked list always required( for tag even if no input data) * /
        if dst_dma_list == DMA_MAPPING_ERROR:
            return -EINVAL

        # If input data present ensure src linked list is created * /
        if src_size and src_dma_list == DMA_MAPPING_ERROR:
            return -EINVAL

        return 0
    return -EINVAL


'''
/**
 * ocs_aes_op() - Perform AES/SM4 operation.
 * @aes_dev:		The OCS AES device to use.
 * @mode:		The mode to use (ECB, CBC, CTR, or CTS).
 * @cipher:		The cipher to use (AES or SM4).
 * @instruction:	The instruction to perform (encrypt or decrypt).
 * @dst_dma_list:	The OCS DMA list mapping output memory.
 * @src_dma_list:	The OCS DMA list mapping input payload data.
 * @src_size:		The amount of data mapped by @src_dma_list.
 * @iv:			The IV vector.
 * @iv_size:		The size (in bytes) of @iv.
 *
 * Return: 0 on success, negative error code otherwise.
 */
'''


def ocs_aes_op(aes_dev,
               mode,
               cipher,
               instruction,
               dst_dma_list,
               src_dma_list,
               src_size,
               iv,
               iv_size):
    rc = ocs_aes_validate_inputs(src_dma_list, src_size, iv, iv_size, 0, 0,
                                 None, 0, cipher, mode, instruction,
                                 dst_dma_list)
    if rc != 0:
        return rc

    '''
    /*
	 * ocs_aes_validate_inputs() is a generic check, now ensure mode is not
	 * GCM or CCM.
	 */
    '''
    if mode == ocs_mode.OCS_MODE_GCM or mode == ocs_mode.OCS_MODE_CCM:
        return -EINVAL

    # Cast IV to u32 array.
    iv32_size = 4
    iv32 = [0] * iv32_size
    # iv_size == 16
    for i in range(iv_size // 4):
        val32 = iv[i * iv32_size]  # 3 byte
        val32 <<= 8
        val32 |= iv[i * iv32_size + 1]  # 2 byte
        val32 <<= 8
        val32 |= iv[i * iv32_size + 2]  # 1 byte
        val32 <<= 8
        val32 |= iv[i * iv32_size + 3]  # 0 byte

        iv32[i] = val32

    ocs_aes_init(aes_dev, mode, cipher, instruction)

    if mode == ocs_mode.OCS_MODE_CTS:
        # Write the byte length of the last data block to engine.
        ocs_aes_write_last_data_blk_len(aes_dev, src_size)

    # ECB is the only mode that doesn't use IV.
    if mode != ocs_mode.OCS_MODE_ECB:
        iowrite32(iv32[0], aes_dev.base_reg + AES_IV_0_OFFSET)
        iowrite32(iv32[1], aes_dev.base_reg + AES_IV_1_OFFSET)
        iowrite32(iv32[2], aes_dev.base_reg + AES_IV_2_OFFSET)
        iowrite32(iv32[3], aes_dev.base_reg + AES_IV_3_OFFSET)

    # Set AES_ACTIVE.TRIGGER to start the operation.
    aes_a_op_trigger(aes_dev)

    # Configure and activate input / output DMA.
    dma_to_ocs_aes_ll(aes_dev, src_dma_list)
    dma_from_ocs_aes_ll(aes_dev, dst_dma_list)
    aes_a_dma_active_src_dst_ll_en(aes_dev)

    if mode == ocs_mode.OCS_MODE_CTS:
        # / *
        # * For CTS mode, instruct engine to activate ciphertext
        # * stealing if last block of data is incomplete.
        # * /
        aes_a_set_last_gcx(aes_dev)
    else:
        # For all other modes, just write the 'termination' bit.
        aes_a_op_termination(aes_dev)

    # Wait for engine to complete processing.
    rc = ocs_aes_irq_enable_and_wait(aes_dev, AES_COMPLETE_INT)
    if rc != 0:
        return rc

    if mode == ocs_mode.OCS_MODE_CTR:
        # Read back IV for streaming mode * /
        iv32[0] = ioread32(aes_dev.base_reg + AES_IV_0_OFFSET)
        iv32[1] = ioread32(aes_dev.base_reg + AES_IV_1_OFFSET)
        iv32[2] = ioread32(aes_dev.base_reg + AES_IV_2_OFFSET)
        iv32[3] = ioread32(aes_dev.base_reg + AES_IV_3_OFFSET)

        mask_8_bit = bit_mask(8)

        for i in range(iv32_size):
            iv[i * iv32_size] = iv32[i] & mask_8_bit
            iv[i * iv32_size + 1] = (iv32[i] >> 8) & mask_8_bit
            iv[i * iv32_size + 2] = (iv32[i] >> 16) & mask_8_bit
            iv[i * iv32_size + 3] = (iv32[i] >> 24) & mask_8_bit

    return 0


# Compute and write J0 to engine registers.
'''/*
	 * IV must be 12 bytes; Other sizes not supported as Linux crypto API
	 * does only expects/allows 12 byte IV for GCM
	 */
'''


def ocs_aes_gcm_write_j0(aes_dev,
                         iv):
    # Cast IV to u32 array.
    iv32_size = 4
    j0 = [0] * iv32_size
    # iv_size == 16
    for i in range(4):
        val32 = iv[i * iv32_size]  # 3 byte
        val32 <<= 8
        val32 |= iv[i * iv32_size + 1]  # 2 byte
        val32 <<= 8
        val32 |= iv[i * iv32_size + 2]  # 1 byte
        val32 <<= 8
        val32 |= iv[i * iv32_size + 3]  # 0 byte

        j0[i] = val32

    iowrite32(0x00000001, aes_dev.base_reg + AES_IV_0_OFFSET)
    iowrite32(swab32(j0[2]), aes_dev.base_reg + AES_IV_1_OFFSET)
    iowrite32(swab32(j0[1]), aes_dev.base_reg + AES_IV_2_OFFSET)
    iowrite32(swab32(j0[0]), aes_dev.base_reg + AES_IV_3_OFFSET)


# Read GCM tag from engine registers.
def ocs_aes_gcm_read_tag(aes_dev,
                         tag, tag_size):
    tag_u32 = [0] * AES_MAX_TAG_SIZE_U32
    '''
    /*
	 * The Authentication Tag T is stored in Little Endian order in the
	 * registers with the most significant bytes stored from AES_T_MAC[3]
	 * downward.
	 */
    '''
    tag_u32[0] = swab32(ioread32(aes_dev.base_reg + AES_T_MAC_3_OFFSET))
    tag_u32[1] = swab32(ioread32(aes_dev.base_reg + AES_T_MAC_2_OFFSET))
    tag_u32[2] = swab32(ioread32(aes_dev.base_reg + AES_T_MAC_1_OFFSET))
    tag_u32[3] = swab32(ioread32(aes_dev.base_reg + AES_T_MAC_0_OFFSET))

    mask_8_bit = bit_mask(8)

    for i in range(AES_MAX_TAG_SIZE_U32):
        tag[i * AES_MAX_TAG_SIZE_U32] = tag_u32[i] & mask_8_bit
        tag[i * AES_MAX_TAG_SIZE_U32 + 1] = (tag_u32[i] >> 8) & mask_8_bit
        tag[i * AES_MAX_TAG_SIZE_U32 + 2] = (tag_u32[i] >> 16) & mask_8_bit
        tag[i * AES_MAX_TAG_SIZE_U32 + 3] = (tag_u32[i] >> 24) & mask_8_bit


'''
/**
 * ocs_aes_gcm_op() - Perform GCM operation.
 * @aes_dev:		The OCS AES device to use.
 * @cipher:		The Cipher to use (AES or SM4).
 * @instruction:	The instruction to perform (encrypt or decrypt).
 * @dst_dma_list:	The OCS DMA list mapping output memory.
 * @src_dma_list:	The OCS DMA list mapping input payload data.
 * @src_size:		The amount of data mapped by @src_dma_list.
 * @iv:			The input IV vector.
 * @aad_dma_list:	The OCS DMA list mapping input AAD data.
 * @aad_size:		The amount of data mapped by @aad_dma_list.
 * @out_tag:		Where to store computed tag.
 * @tag_size:		The size (in bytes) of @out_tag.
 *
 * Return: 0 on success, negative error code otherwise.
 */
'''


def ocs_aes_gcm_op(aes_dev,
                   cipher,
                   instruction,
                   dst_dma_list,
                   src_dma_list,
                   src_size,
                   iv,
                   aad_dma_list,
                   aad_size,
                   out_tag,
                   tag_size):
    rc = ocs_aes_validate_inputs(src_dma_list, src_size, iv,
                                 GCM_AES_IV_SIZE, aad_dma_list,
                                 aad_size, out_tag, tag_size, cipher,
                                 ocs_mode.OCS_MODE_GCM, instruction,
                                 dst_dma_list)
    if rc != 0:
        return rc

    ocs_aes_init(aes_dev, ocs_mode.OCS_MODE_GCM, cipher, instruction)

    # Compute and write J0 to OCS HW.
    ocs_aes_gcm_write_j0(aes_dev, iv)

    # Write out_tag byte length
    iowrite32(tag_size, aes_dev.base_reg + AES_TLEN_OFFSET)

    # Write the byte length of the last plaintext / ciphertext block.
    ocs_aes_write_last_data_blk_len(aes_dev, src_size)

    # Write ciphertext bit length
    mask_64_bit = bit_mask(64)
    bit_len = (src_size * 8) & mask_64_bit
    val = bit_len & 0xFFFFFFFF
    iowrite32(val, aes_dev.base_reg + AES_MULTIPURPOSE2_0_OFFSET)
    val = bit_len >> 32
    iowrite32(val, aes_dev.base_reg + AES_MULTIPURPOSE2_1_OFFSET)

    # Write aad bit length
    bit_len = (aad_size * 8) & mask_64_bit
    val = bit_len & 0xFFFFFFFF
    iowrite32(val, aes_dev.base_reg + AES_MULTIPURPOSE2_2_OFFSET)
    val = bit_len >> 32
    iowrite32(val, aes_dev.base_reg + AES_MULTIPURPOSE2_3_OFFSET)

    # Set AES_ACTIVE.TRIGGER to start the operation.
    aes_a_op_trigger(aes_dev)

    # Process AAD.
    if aad_size != 0:
        # If aad present, configure DMA to feed it to the engine.
        dma_to_ocs_aes_ll(aes_dev, aad_dma_list)
        aes_a_dma_active_src_ll_en(aes_dev)

        # Instructs engine to pad last block of aad, if needed.
        aes_a_set_last_gcx_and_adata(aes_dev)

        # Wait for DMA transfer to complete.
        rc = ocs_aes_irq_enable_and_wait(aes_dev, AES_DMA_SRC_DONE_INT)
        if rc != 0:
            return rc
    else:
        aes_a_set_last_gcx_and_adata(aes_dev)

    # Wait until adata( if present) has been processed.
    aes_a_wait_last_gcx(aes_dev)
    aes_a_dma_wait_input_buffer_occupancy(aes_dev)

    # Now process payload.
    if src_size != 0:
        # Configure and activate DMA for both input and output data.
        dma_to_ocs_aes_ll(aes_dev, src_dma_list)
        dma_from_ocs_aes_ll(aes_dev, dst_dma_list)
        aes_a_dma_active_src_dst_ll_en(aes_dev)
    else:
        aes_a_dma_set_xfer_size_zero(aes_dev)
        aes_a_dma_active(aes_dev)

    # Instruct AES / SMA4 engine payload processing is over.
    aes_a_set_last_gcx(aes_dev)

    # Wait for OCS AES engine to complete processing.
    rc = ocs_aes_irq_enable_and_wait(aes_dev, AES_COMPLETE_INT)

    if rc != 0:
        return rc

    ocs_aes_gcm_read_tag(aes_dev, out_tag, tag_size)

    return 0


# Write encrypted tag to AES/SM4 engine.

def ocs_aes_ccm_write_encrypted_tag(aes_dev, in_tag, tag_size):
    # Ensure DMA input buffer is empty
    aes_a_dma_wait_input_buffer_occupancy(aes_dev)

    '''
    /*
	 * During CCM decrypt, the OCS block needs to finish processing the
	 * ciphertext before the tag is written.  So delay needed after DMA has
	 * completed writing the ciphertext
	 */
    '''

    aes_a_dma_reset_and_activate_perf_cntr(aes_dev)
    aes_a_dma_wait_and_deactivate_perf_cntr(aes_dev,
                                            CCM_DECRYPT_DELAY_TAG_CLK_COUNT)

    # Write encrypted tag to AES/SM4 engine.
    for i in range(tag_size):
        iowrite8(in_tag[i], aes_dev.base_reg +
                 AES_A_DMA_INBUFFER_WRITE_FIFO_OFFSET)


'''
/*
 * Write B0 CCM block to OCS AES HW.
 *
 * Note: B0 format is documented in NIST Special Publication 800-38C
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
 * (see Section A.2.1)
 */
'''


def ocs_aes_ccm_write_b0(aes_dev,
                         iv, adata_size, tag_size,
                         cryptlen):
    b0 = [0] * 16
    '''
    /*
	 * B0[0] is the 'Flags Octet' and has the following structure:
	 *   bit 7: Reserved
	 *   bit 6: Adata flag
	 *   bit 5-3: t value encoded as (t-2)/2
	 *   bit 2-0: q value encoded as q - 1
	 */
    '''
    # If there is AAD data, set the Adata flag.

    if adata_size != 0:
        b0[0] |= bit(6)

    '''
    /*
	 * t denotes the octet length of T.
	 * t can only be an element of { 4, 6, 8, 10, 12, 14, 16} and is
	 * encoded as (t - 2) / 2
	 */
    '''
    b0[0] |= (((tag_size - 2) // 2) & 0x7) << 3
    '''
    /*
	 * q is the octet length of Q.
	 * q can only be an element of {2, 3, 4, 5, 6, 7, 8} and is encoded as
	 * q - 1 == iv[0] & 0x7;
	 */
    '''
    b0[0] |= iv[0] & 0x7
    '''
    /*
	 * Copy the Nonce N from IV to B0; N is located in iv[1]..iv[15 - q]
	 * and must be copied to b0[1]..b0[15-q].
	 * q == (iv[0] & 0x7) + 1
	 */
    '''
    q = (iv[0] & 0x7) + 1
    for i in range(1, 15 - q):
        b0[i] = iv[i]
    '''
    /*
	 * The rest of B0 must contain Q, i.e., the message length.
	 * Q is encoded in q octets, in big-endian order, so to write it, we
	 * start from the end of B0 and we move backward.
	 */
    '''
    i = 15  # sizeof(b0) - 1
    while q != 0:
        b0[i] = cryptlen & 0xff
        cryptlen >>= 8
        i = i - 1
        q = q - 1
    '''
    /*
	 * If cryptlen is not zero at this point, it means that its original
	 * value was too big.
	 */
    '''
    if cryptlen != 0:
        return -EOVERFLOW
    # Now write B0 to OCS AES input buffer.
    for i in range(16):
        iowrite8(b0[i], aes_dev.base_reg +
                 AES_A_DMA_INBUFFER_WRITE_FIFO_OFFSET)

    return 0


'''
/*
 * Write adata length to OCS AES HW.
 *
 * Note: adata len encoding is documented in NIST Special Publication 800-38C
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
 * (see Section A.2.2)
 */
'''


def ocs_aes_ccm_write_adata_len(aes_dev,
                                adata_len):
    enc_a = [0] * 10  # maximum 10 octets
    len = 0
    mask_8_bit = bit_mask(8)
    if adata_len < 65280:
        len = 2
        enc_a[0] = adata_len & mask_8_bit
        enc_a[1] = (adata_len >> 8) & mask_8_bit
    elif (adata_len <= 0xFFFFFFFF):
        len = 6
        enc_a[0] = 0xff
        enc_a[1] = 0xfe
        enc_a[2] = (adata_len >> 24) & mask_8_bit
        enc_a[3] = (adata_len >> 16) & mask_8_bit
        enc_a[4] = (adata_len >> 8) & mask_8_bit
        enc_a[5] = adata_len & mask_8_bit
    else:  # adata_len >= 2 ^ 32
        len = 10
        enc_a[0] = 0xff
        enc_a[1] = 0xff
        for i in range(2, 10):
            shift_offset = 64 - (i - 1) * 8
            if shift_offset != 0:
                enc_a[i] = (adata_len >> shift_offset) & mask_8_bit
            else:
                enc_a[i] = adata_len & mask_8_bit

    for i in range(len):
        iowrite8(enc_a[i], aes_dev.base_reg +
                 AES_A_DMA_INBUFFER_WRITE_FIFO_OFFSET)


def ocs_aes_ccm_do_adata(aes_dev,
                         adata_dma_list, adata_size):
    if adata_size != 0:
        # Since no aad the LAST_GCX bit can be set now * /
        aes_a_set_last_gcx_and_adata(aes_dev)

        # Wait until adata( if present) has been processed.
        aes_a_wait_last_gcx(aes_dev)
        aes_a_dma_wait_input_buffer_occupancy(aes_dev)

    # Adata case.
    '''
    /*
	 * Form the encoding of the Associated data length and write it
	 * to the AES/SM4 input buffer.
	 */
    '''
    ocs_aes_ccm_write_adata_len(aes_dev, adata_size)

    # Configure the AES/SM4 DMA to fetch the Associated Data
    dma_to_ocs_aes_ll(aes_dev, adata_dma_list)

    # Activate DMA to fetch Associated data.
    aes_a_dma_active_src_ll_en(aes_dev)

    # Set LAST_GCX and LAST_ADATA in AES ACTIVE register.
    aes_a_set_last_gcx_and_adata(aes_dev)

    # Wait for DMA transfer to complete.
    rc = ocs_aes_irq_enable_and_wait(aes_dev, AES_DMA_SRC_DONE_INT)
    if rc != 0:
        return rc

    # Wait until adata( if present) has been processed.
    aes_a_wait_last_gcx(aes_dev)
    aes_a_dma_wait_input_buffer_occupancy(aes_dev)

    return 0


def ocs_aes_ccm_encrypt_do_payload(aes_dev,
                                   dst_dma_list,
                                   src_dma_list,
                                   src_size):
    if src_size != 0:
        # / *
        # * Configure and activate DMA for both input and output
        # * data.
        # * /
        dma_to_ocs_aes_ll(aes_dev, src_dma_list)
        dma_from_ocs_aes_ll(aes_dev, dst_dma_list)
        aes_a_dma_active_src_dst_ll_en(aes_dev)
    else:
        # / * Configure and activate DMA for output data only.* /
        dma_from_ocs_aes_ll(aes_dev, dst_dma_list)
        aes_a_dma_active_dst_ll_en(aes_dev)
    '''
    /*
	 * Set the LAST GCX bit in AES_ACTIVE Register to instruct
	 * AES/SM4 engine to pad the last block of data.
	 */
    '''
    aes_a_set_last_gcx(aes_dev)

    # We are done, wait for IRQ and return.
    return ocs_aes_irq_enable_and_wait(aes_dev, AES_COMPLETE_INT)


def ocs_aes_ccm_decrypt_do_payload(aes_dev,
                                   dst_dma_list,
                                   src_dma_list,
                                   src_size):
    if src_size != 0:
        # / * Let engine process 0-length input.* /
        aes_a_dma_set_xfer_size_zero(aes_dev)
        aes_a_dma_active(aes_dev)
        aes_a_set_last_gcx(aes_dev)
        return 0

    '''
    /*
	 * Configure and activate DMA for both input and output
	 * data.
	 */
    '''
    dma_to_ocs_aes_ll(aes_dev, src_dma_list)
    dma_from_ocs_aes_ll(aes_dev, dst_dma_list)
    aes_a_dma_active_src_dst_ll_en(aes_dev)

    '''
    /*
	 * Set the LAST GCX bit in AES_ACTIVE Register; this allows the
	 * AES/SM4 engine to differentiate between encrypted data and
	 * encrypted MAC.
	 */
    '''
    aes_a_set_last_gcx(aes_dev)
    '''
    /*
	  * Enable DMA DONE interrupt; once DMA transfer is over,
	  * interrupt handler will process the MAC/tag.
	  */
    '''
    return ocs_aes_irq_enable_and_wait(aes_dev, AES_DMA_SRC_DONE_INT)


'''
/*
 * Compare Tag to Yr.
 *
 * Only used at the end of CCM decrypt. If tag == yr, message authentication
 * has succeeded.
 */
'''


def ccm_compare_tag_to_yr(aes_dev,
                          tag_size_bytes):
    tag = [0] * AES_MAX_TAG_SIZE_U32
    yr = [0] * AES_MAX_TAG_SIZE_U32

    u32_size = 4  # sizeof(32)
    # Read Tag and Yr from AES registers.
    for i in range(AES_MAX_TAG_SIZE_U32):
        tag[i] = ioread32(aes_dev.base_reg +
                          AES_T_MAC_0_OFFSET + (i * u32_size))
        yr[i] = ioread32(aes_dev.base_reg +
                         AES_MULTIPURPOSE2_0_OFFSET +
                         (i * u32_size))
        if tag[i] - yr[i] != 0:
            return -EBADMSG

    return 0


'''
/**
 * ocs_aes_ccm_op() - Perform CCM operation.
 * @aes_dev:		The OCS AES device to use.
 * @cipher:		The Cipher to use (AES or SM4).
 * @instruction:	The instruction to perform (encrypt or decrypt).
 * @dst_dma_list:	The OCS DMA list mapping output memory.
 * @src_dma_list:	The OCS DMA list mapping input payload data.
 * @src_size:		The amount of data mapped by @src_dma_list.
 * @iv:			The input IV vector.
 * @adata_dma_list:	The OCS DMA list mapping input A-data.
 * @adata_size:		The amount of data mapped by @adata_dma_list.
 * @in_tag:		Input tag.
 * @tag_size:		The size (in bytes) of @in_tag.
 *
 * Note: for encrypt the tag is appended to the ciphertext (in the memory
 *	 mapped by @dst_dma_list).
 *
 * Return: 0 on success, negative error code otherwise.
 */
'''


def ocs_aes_ccm_op(aes_dev,
                   cipher,
                   instruction,
                   dst_dma_list,
                   src_dma_list,
                   src_size,
                   iv,
                   adata_dma_list,
                   adata_size,
                   in_tag,
                   tag_size):
    rc = ocs_aes_validate_inputs(src_dma_list, src_size, iv,
                                 AES_BLOCK_SIZE, adata_dma_list, adata_size,
                                 in_tag, tag_size, cipher, ocs_mode.OCS_MODE_CCM,
                                 instruction, dst_dma_list)
    if rc != 0:
        return rc

    ocs_aes_init(aes_dev, ocs_mode.OCS_MODE_CCM, cipher, instruction)

    '''
    /*
	 * Note: rfc 3610 and NIST 800-38C require counter of zero to encrypt
	 * auth tag so ensure this is the case
	 */
    '''
    lprime = iv[L_PRIME_IDX]
    # memset
    for i in range(COUNTER_START(lprime), COUNTER_LEN(lprime)):
        iv[i] = 0

    '''
    /*
	 * Nonce is already converted to ctr0 before being passed into this
	 * function as iv.
	 */
    '''
    iv32_size = 4
    iv_32 = [0] * iv32_size
    # iv_size == 16
    for i in range(4):
        val32 = iv[i * iv32_size]  # 3 byte
        val32 <<= 8
        val32 |= iv[i * iv32_size + 1]  # 2 byte
        val32 <<= 8
        val32 |= iv[i * iv32_size + 2]  # 1 byte
        val32 <<= 8
        val32 |= iv[i * iv32_size + 3]  # 0 byte

        iv_32[i] = val32

    iowrite32(swab32(iv_32[0]),
              aes_dev.base_reg + AES_MULTIPURPOSE1_3_OFFSET)
    iowrite32(swab32(iv_32[1]),
              aes_dev.base_reg + AES_MULTIPURPOSE1_2_OFFSET)
    iowrite32(swab32(iv_32[2]),
              aes_dev.base_reg + AES_MULTIPURPOSE1_1_OFFSET)
    iowrite32(swab32(iv_32[3]),
              aes_dev.base_reg + AES_MULTIPURPOSE1_0_OFFSET)

    # Write MAC/tag length in register AES_TLEN

    iowrite32(tag_size, aes_dev.base_reg + AES_TLEN_OFFSET)

    '''
    /*
	 * Write the byte length of the last AES/SM4 block of Payload data
	 * (without zero padding and without the length of the MAC) in register
	 * AES_PLEN.
	 */
    '''
    ocs_aes_write_last_data_blk_len(aes_dev, src_size)

    # Set AES_ACTIVE.TRIGGER to start the operation.

    aes_a_op_trigger(aes_dev)

    aes_a_dma_reset_and_activate_perf_cntr(aes_dev)

    # Form block B0 and write it to the AES/SM4 input buffer.
    rc = ocs_aes_ccm_write_b0(aes_dev, iv, adata_size, tag_size, src_size)
    if rc != 0:
        return rc

    '''
    /*
	 * Ensure there has been at least CCM_DECRYPT_DELAY_LAST_GCX_CLK_COUNT
	 * clock cycles since TRIGGER bit was set
	 */
    '''
    aes_a_dma_wait_and_deactivate_perf_cntr(aes_dev,
                                            CCM_DECRYPT_DELAY_LAST_GCX_CLK_COUNT)
    # Process Adata.
    ocs_aes_ccm_do_adata(aes_dev, adata_dma_list, adata_size)

    # For Encrypt case we just process the payload and return.

    if instruction == ocs_instruction.OCS_ENCRYPT:
        return ocs_aes_ccm_encrypt_do_payload(aes_dev, dst_dma_list,
                                              src_dma_list, src_size)

    # For Decypt we need to process the payload and then the tag.
    rc = ocs_aes_ccm_decrypt_do_payload(aes_dev, dst_dma_list,
                                        src_dma_list, src_size)
    if rc != 0:
        return rc

    # Process MAC/tag directly: feed tag to engine and wait for IRQ.

    ocs_aes_ccm_write_encrypted_tag(aes_dev, in_tag, tag_size)
    rc = ocs_aes_irq_enable_and_wait(aes_dev, AES_COMPLETE_INT)
    if rc != 0:
        return rc

    return ccm_compare_tag_to_yr(aes_dev, tag_size)


def ocs_aes_bypass_op(aes_dev,
                      dst_dma_list,
                      src_dma_list, src_size):
    return ocs_aes_op(aes_dev, ocs_mode.OCS_MODE_ECB, ocs_cipher.OCS_AES, ocs_instruction.OCS_BYPASS,
                      dst_dma_list, src_dma_list, src_size, None, 0)


'''
/**
 * ocs_create_linked_list_from_sg() - Create OCS DMA linked list from SG list.
 * @aes_dev:	  The OCS AES device the list will be created for.
 * @sg:		  The SG list OCS DMA linked list will be created from. When
 *		  passed to this function, @sg must have been already mapped
 *		  with dma_map_sg().
 * @sg_dma_count: The number of DMA-mapped entries in @sg. This must be the
 *		  value returned by dma_map_sg() when @sg was mapped.
 * @dll_desc:	  The OCS DMA dma_list to use to store information about the
 *		  created linked list.
 * @data_size:	  The size of the data (from the SG list) to be mapped into the
 *		  OCS DMA linked list.
 * @data_offset:  The offset (within the SG list) of the data to be mapped.
 *
 * Return:	0 on success, negative error code otherwise.
 */
'''

'''

def ocs_create_linked_list_from_sg(aes_dev: ocs_aes_dev,
                                   sg: scatterlist,
                                   sg_dma_count: int,
                                   dll_desc: ocs_dll_desc,
                                   data_size: int,
                                   data_offset: int):
    ll = None
    sg_tmp = scatterlist()

    if dll_desc is None or sg is None or aes_dev is None:
        return -EINVAL

    # Default values for when no ddl_desc is created.
    dll_desc.vaddr = 0
    dll_desc.dma_addr = DMA_MAPPING_ERROR
    dll_desc.size = 0

    if data_size == 0:
        return 0

    # Loop over sg_list until we reach entry at specified offset.

    while data_offset >= sg_dma_len(sg):
        data_offset -= sg_dma_len(sg)
        sg_dma_count -= 1
        sg = sg_next(sg)
        # If we reach the end of the list, offset was invalid.
        if sg is None or sg_dma_count == 0:
            return -EINVAL

    # Compute number of DMA-mapped SG entries to add into OCS DMA list.

    dma_nents = 0
    tmp = 0
    sg_tmp = sg
    while (tmp < data_offset + data_size):
        # If we reach the end of the list, data_size was invalid.
        if sg_tmp != None:
            return -EINVAL
        tmp += sg_dma_len(sg_tmp)
        dma_nents += 1
        sg_tmp = sg_next(sg_tmp)

    if dma_nents > sg_dma_count:
        return -EINVAL

    # Allocate the DMA list, one entry for each SG entry.
    dll_desc.size = 16 * dma_nents  # sizeof(ocs_dma_linked_list) = 16
    dll_desc.vaddr = dma_alloc_coherent(aes_dev.dev, dll_desc.size,
                                        dll_desc.dma_addr, GFP_KERNEL)
    if dll_desc.vaddr == 0:
        return -ENOMEM

    # Populate DMA linked list entries.
    ll = dll_desc.vaddr

    for i in range(dma_nents):
        ll[i].src_addr = sg_dma_address(sg) + data_offset
        if sg_dma_len(sg) - data_offset < data_size:
            ll[i].src_len = sg_dma_len(sg) - data_offset
        else:
            ll[i].src_len = data_size
        data_offset = 0
        data_size -= ll[i].src_len
        # Current element points to the DMA address  of the next one.
        ll[i].next = dll_desc.dma_addr + (16 * (i + 1))  # sizeof(*ll) = 16
        ll[i].ll_flags = 0
        sg = sg_next(sg)

    # Terminate last element.
    i = dma_nents
    ll[i - 1].next = 0
    ll[i - 1].ll_flags = OCS_LL_DMA_FLAG_TERMINATE

    return 0
'''
