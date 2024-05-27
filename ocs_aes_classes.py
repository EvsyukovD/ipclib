# Resource: https://elixir.bootlin.com/linux/v6.7.2/source/drivers/crypto/intel/keembay/ocs-aes.h
from dev_common import iowrite32, ioread32
AES_BLOCK_SIZE = 16
GCM_AES_IV_SIZE = 12


class scatterlist(object):
    def __init__(self):
        self.page_link = 0
        self.offset = 0
        self.length = 0
        self.dma_address = 0
        self.dma_length = 0
        self.dma_flags = 0

def sg_is_chain(sg):
    return sg.page_link & 0x01

def sg_is_last(sg):
    return sg.page_link & 0x02

def sg_chain_ptr(sg):
    pass

def sg_next(sg):
    pass

def sg_dma_len(sg):
    return sg.dma_length

def sg_dma_address(sg):
    return sg.dma_address

class ocs_cipher(object):
    OCS_AES = 0
    OCS_SM4 = 1


class ocs_mode(object):
    OCS_MODE_ECB = 0
    OCS_MODE_CBC = 1
    OCS_MODE_CTR = 2
    OCS_MODE_CCM = 6
    OCS_MODE_GCM = 7
    OCS_MODE_CTS = 9


class ocs_instruction(object):
    OCS_ENCRYPT = 0
    OCS_DECRYPT = 1
    OCS_EXPAND = 2
    OCS_BYPASS = 3



'''
/**
 * struct ocs_aes_dev - AES device context.
 * @list:			List head for insertion into device list hold
 *				by driver.
 * @dev:			OCS AES device.
 * @irq:			IRQ number.
 * @base_reg:			IO base address of OCS AES.
 * @irq_copy_completion:	Completion to indicate IRQ has been triggered.
 * @dma_err_mask:		Error reported by OCS DMA interrupts.
 * @engine:			Crypto engine for the device.
 */
 struct ocs_aes_dev {
	struct list_head list;
	struct device *dev;
	int irq;
	void __iomem *base_reg;
	struct completion irq_completion;
	u32 dma_err_mask;
	struct crypto_engine *engine;
};
'''


class ocs_aes_dev(object):
    def __init__(self):
        self.list = None
        self.dev = None
        self.irq = 0
        self.base_reg = 0
        self.completion = None
        self.dma_err_mask = 0
        self.engine = None


'''
/**
 * struct ocs_dll_desc - Descriptor of an OCS DMA Linked List.
 * @vaddr:	Virtual address of the linked list head.
 * @dma_addr:	DMA address of the linked list head.
 * @size:	Size (in bytes) of the linked list.
 */
struct ocs_dll_desc {
	void		*vaddr;
	dma_addr_t	dma_addr;
	size_t		size;
};
'''


class ocs_dll_desc(object):
    def __init__(self):
        self.vaddr = 0
        self.dma_addr = 0
        self.size = 0


