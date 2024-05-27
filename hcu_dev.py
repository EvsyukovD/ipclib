from utils import *
from mem import phys, memdump_ds
from ocs_hcu_classes import *
from ocs_hcu_interaction import *
from dev_common import *

HCU_A_DMA_SRC_ADDR_OFFSET = 0x0400
HCU_A_DMA_DST_ADDR_OFFSET = 0x0404
HCU_A_DMA_SRC_SIZE_OFFSET = 0x0408
HCU_A_DMA_DST_SIZE_OFFSET = 0x040C
HCU_A_DMA_DMA_MODE_OFFSET = 0x0410
HCU_A_DMA_NEXT_SRC_DESCR_OFFSET = 0x0418
HCU_A_DMA_NEXT_DST_DESCR_OFFSET = 0x041C
HCU_BASE = 0xf510b000


def hash_data(data, data_len, algo):
    HCU_BASE_ADDRESS = 0xF510B000
    hcu_dev = ocs_hcu_dev()
    hcu_dev.io_base = HCU_BASE_ADDRESS

    dgst_size = ocs_hcu_digest_size(algo)
    dgst = bytearray([0] * dgst_size)
    ctx = ocs_hcu_hash_ctx()

    t.halt()
    ocs_hcu_get_digest(hcu_dev,
                       algo,
                       dgst,
                       dgst_size)
    print("Init Digest:")
    res = "0x"
    for i in dgst:
        res += str(hex(i))[2:]
    print(res)

    ocs_hcu_hash_init(ctx, algo)

    dma_list = ocs_hcu_dma_list_alloc(hcu_dev, 10000)  # stupid value for max_nents

    data_addr = alloc_bytes(data, data_len, hcu_dev.io_base + 0x600)

    # print("[DEBUG] Data address: %s" % str(hex(data_addr)))
    # print("Data for loading: %s" % str(data))
    # t.memdump(phys(data_addr), data_len, 1)

    # log("[DEBUG] Allocated bytes of string %s:" % str(data))
    # t.memdump(phys(data_addr), data_len, 1)

    ocs_hcu_dma_list_add_tail(hcu_dev, dma_list, addr=data_addr, length=data_len)

    print("List:")
    t.memdump(phys(dma_list.dma_addr), 0x20, 1)

    # ocs_hcu_digest(hcu_dev, algo, data, data_len, dgst, dgst_size)

    ocs_hcu_hash_finup(hcu_dev, ctx, dma_list, dgst, dgst_size)

    irqs = (0, 0)

    ocs_hcu_irq_handler(0, hcu_dev, irqs)

    print("Irqs : hash irqs %s, dma irqs %s" % (bin(irqs[0]), bin(irqs[1])))
    print("DMA errors:")
    print_dma_errors(irqs[1])

    return dgst


'''
Rewrite hash_data
'''


def hcu_hash(data, data_len, algo):
    # Init some values
    HCU_BASE_ADDRESS = 0xF510B000
    hcu_dev = ocs_hcu_dev()
    hcu_dev.io_base = HCU_BASE_ADDRESS

    # Set data allocation memory offset
    HCU_DMA_INBUFFER_OFFSET = 0x600
    HCU_DATA_OFFSET = 0x600
    MEM_DATA_ADDR = 0x100
    HCU_DMA_LIST_ADDR = 0x800  # 0x6006140

    # Create digest bytearray
    dgst_len = ocs_hcu_digest_size(algo)
    dgst = bytearray([0] * dgst_len)
    ctx = ocs_hcu_hash_ctx()
    ctx.algo = algo

    # Allocate data in memory
    data_addr = alloc_bytes(data, data_len, MEM_DATA_ADDR)

    # Allocate list
    dma_list = ocs_hcu_dma_list_alloc(hcu_dev, 10000, HCU_DMA_LIST_ADDR)

    # Add new tail
    ocs_hcu_dma_list_add_tail(hcu_dev, dma_list, data_addr, data_len)

    ocs_hcu_hash_finup(hcu_dev, ctx, dma_list, dgst, dgst_len)

    irqs = (0, 0)
    # Handle possible errors
    ocs_hcu_irq_handler(0, hcu_dev, irqs)

    print("Irqs : hash irqs %s, dma irqs %s" % (bin(irqs[0]), bin(irqs[1])))
    print("DMA errors:")
    print_dma_errors(irqs[1])
    # Dump some memory
    # mem_addr = HCU_BASE_ADDRESS + 0x600
    # print("Dump memory at address %s" % hex(mem_addr))
    # size = 0x1000 - 0x600
    # t.memdump(phys(mem_addr), size, 1)
    return dgst


def get_hash(data, data_len, algo):
    # Create digest bytearray
    dgst_size = ocs_hcu_digest_size(algo)
    dgst = bytearray([0] * dgst_size)
    ctx = ocs_hcu_hash_ctx()

    custom_finup(data, data_len, ctx, dgst, dgst_size)

    return dgst


def custom_finup(data, data_len, ctx, dgst, dgst_size):
    hcu_dev = ocs_hcu_dev()
    HCU_BASE_ADDRESS = 0xF510B000
    hcu_dev.io_base = HCU_BASE_ADDRESS

    MEM_DATA_ADDR = 0x100

    data_addr = alloc_bytes(data, data_len, MEM_DATA_ADDR)
    # Configure the hardware for the current request.
    rc = ocs_hcu_hw_cfg(hcu_dev, ctx.algo, False)
    if rc != 0:
        return rc

    # If we already processed some data, idata needs to be set.
    if ctx.idata.msg_len_lo != 0 or ctx.idata.msg_len_hi != 0:
        ocs_hcu_set_intermediate_data(hcu_dev, ctx.idata, ctx.algo)

    writel(OCS_HCU_START, hcu_dev.io_base + OCS_HCU_OPERATION)

    hcu_dma_cfg(data_addr, data_len, data_addr, 0)

    write_data_to_one_addr(hcu_dev.io_base + 0x600, data, data_len)

    writel(OCS_HCU_TERMINATE, hcu_dev.io_base + OCS_HCU_OPERATION)

    ocs_hcu_wait_and_disable_irq(hcu_dev)

    # Get digest and return.
    return ocs_hcu_get_digest(hcu_dev, ctx.algo, dgst, dgst_size)


def hcu_dma_cfg(src_addr, src_size, dst_addr, dst_size):
    iowrite32(src_addr, HCU_BASE + HCU_A_DMA_SRC_ADDR_OFFSET)
    iowrite32(src_size, HCU_BASE + HCU_A_DMA_SRC_SIZE_OFFSET)
    iowrite32(dst_addr, HCU_BASE + HCU_A_DMA_DST_ADDR_OFFSET)
    iowrite32(dst_size, HCU_BASE + HCU_A_DMA_DST_SIZE_OFFSET)
    iowrite32(0, HCU_BASE + HCU_A_DMA_NEXT_DST_DESCR_OFFSET)
    iowrite32(0, HCU_BASE + HCU_A_DMA_NEXT_SRC_DESCR_OFFSET)

    val = 0xA4001100
    if dst_addr < 0x10000000:
        val = 0x80001100
    iowrite32(OCS_LL_DMA_FLAG_TERMINATE, HCU_BASE + HCU_A_DMA_DMA_MODE_OFFSET)


def main():
    t.halt()

    #                  Address  32 bit      Size 32 bit         nxt_desc 32 bit      ll_flags (TERMINATE)
    # data = bytearray('\x20\xb6\x10\xf5' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00' +'\x00\x00\x00\x80' + ('\0' * 224))
    # data_len = len(data)

    algo = ocs_hcu_algo.OCS_HCU_ALGO_SHA256

    data = bytearray('A' * 8)
    data_len = len(data)
    print("Data len = %d" % data_len)

    dgst = hcu_hash(data, data_len, algo)
    #iowrite32(0xA8ffffff, HCU_BASE)

    print("Hash:")
    print(''.join(format(x, '02x') for x in dgst))



if __name__ == "__main__":
    main()
