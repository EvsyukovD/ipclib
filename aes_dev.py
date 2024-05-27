from ocs_aes_classes import *
from ocs_hcu_interaction import ocs_hcu_dma_list_alloc, ocs_hcu_dma_list_add_tail, ocs_hcu_dma_list, write_dma_entry
from ocs_aes_interaction import *
from mem import phys

AES_BASE_ADDRESS = 0xf5108000
OCS_AES_DMA_BIT_MASK = bit_mask(32)

# Equal structs. Difference only in fields names
ocs_aes_dma_list = ocs_hcu_dma_list
ocs_aes_dma_entry = ocs_dma_linked_list


def ocs_aes_dma_list_alloc(aes_dev,
                           max_nents):
    dma_list = ocs_aes_dma_list()

    LIST_RAM_ADDRESS = 0x800

    dma_list.dma_addr = LIST_RAM_ADDRESS  # start address of array-list

    dma_list.head = ocs_aes_dma_entry()

    dma_list.max_nents = max_nents

    return dma_list


# Add a new DMA entry at the end of the OCS DMA list.
def ocs_aes_dma_list_add_tail(aes_dev,
                              dma_list,
                              addr, length):
    if length == 0:
        return 0

    if dma_list is None:
        return -EINVAL

    if addr & ~OCS_AES_DMA_BIT_MASK:
        print("Unexpected error: Invalid DMA address for OCS AES")
        return -EINVAL

    old_tail = dma_list.tail
    new_tail = None
    if old_tail is None:
        new_tail = dma_list.head
    else:
        new_tail = ocs_aes_dma_entry()
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


def aes_encrypt(data, key, mode, iv=None):
    if data is None or key is None:
        return -EINVAL
    aes_dev = ocs_aes_dev()
    aes_dev.base_reg = AES_BASE_ADDRESS

    # Use same functions for allocating dma lists because they have the same structure

    data_len = len(data)

    dma_list = ocs_aes_dma_list_alloc(aes_dev, 1000)  # stupid value for max_nents

    data_addr = alloc_bytes(data, data_len, start=0x100)

    ocs_aes_dma_list_add_tail(aes_dev, dma_list, addr=data_addr, length=data_len)

    data_len += 64

    print("Memory before encrypting:")
    t.memdump(phys(data_addr), data_len, 1)

    iv_size = 0

    if not (iv is None):
        iv_size = len(iv)

    ocs_aes_bypass_op(aes_dev, dma_list.dma_addr, dma_list.dma_addr, data_len)

    ocs_aes_set_key(aes_dev, len(key), key, ocs_cipher.OCS_AES)

    ocs_aes_op(aes_dev, mode, ocs_cipher.OCS_AES, ocs_instruction.OCS_ENCRYPT, dma_list.dma_addr, dma_list.dma_addr,
               data_len, iv, iv_size)
    print("Memory after encrypting:")
    t.memdump(phys(data_addr), data_len, 1)

    print("Dump memory at address %s" % str(hex(aes_dev.base_reg + 0x700)))
    t.memdump(phys(aes_dev.base_reg + 0x700), 4, 1)

    print("Dump memory at address %s" % str(hex(dma_list.dma_addr)))
    t.memdump(phys(dma_list.dma_addr), 4, 1)

    # As I understand, ciphertext places at the same address as src dma_list: dma_list.dma_addr

    return dma_list


def test_aes():
    data = bytearray(b'A' * 16)
    key = bytearray([0xff] * (256 // 8))
    iv = bytearray([0xff] * 16)
    mode = ocs_mode.OCS_MODE_CBC
    t.halt()

    dma_list = aes_encrypt(data, key, mode, iv)
    t.memdump(phys(dma_list.dma_addr), 16, 1)
    return 0
