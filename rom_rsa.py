from dev_common import *
from utils import *

RSA_BASE = 0xf510e000

# Offsets
RSA_REG_COMMAND = 0x800
RSA_REG_STATUS = 0x804
RSA_REG_COUNT = 0x808
RSA_REG_IRQ = 0x80C
RSA_MOD_OFFSET = 0x500
RSA_EXP_OFFSET = 0x000
RSA_DATA_OFFSET = 0x300
RSA_RESULT_OFFSET = 0x200

# Status busy
RSA_STS_BUSY = (1 << 0)

# Opcodes
RSA_RESET_OP = 0x6000000
RSA_DO_EXP_OP = 0x1000000

# Input sizes
RSA_DATA_SIZE = 0x100
RSA_EXP_SIZE = 0x100
RSA_MOD_SIZE = 0x100


class rsa_pub_key_struct(object):
    def __init__(self):
        self.exp = None
        self.mod = None


class rsa_data_struct(object):
    def __init__(self):
        self.data = None


def wait_rsa():
    tries = 1000000
    status = ioread32(RSA_BASE + RSA_REG_STATUS)
    while tries != 0 and status & RSA_STS_BUSY:
        tries -= 1
        status = ioread32(RSA_BASE + RSA_REG_STATUS)
    return tries


def do_rsa_reset_operation():
    status = ioread32(RSA_BASE + RSA_REG_STATUS)
    if status & RSA_STS_BUSY == 0:
        iowrite32(RSA_RESET_OP, RSA_BASE + RSA_REG_COMMAND)
        wait_rsa()
    return 0


def rsa_load(pub_key_st, data_st):
    if not (pub_key_st is None or data_st is None):
        exp_len = len(pub_key_st.exp)
        mod_len = len(pub_key_st.mod)
        data_len = len(data_st.data)
        if data_len <= RSA_DATA_SIZE and exp_len <= RSA_EXP_SIZE and mod_len <= RSA_MOD_SIZE:
            do_rsa_reset_operation()
            write_data(pub_key_st.exp, RSA_BASE + RSA_EXP_OFFSET)
            write_data(pub_key_st.mod, RSA_BASE + RSA_MOD_OFFSET)
            write_data(data_st.data, RSA_BASE + RSA_DATA_OFFSET)
            res = (mod_len << 14) & 0x7F0000 | 0x21000000
            iowrite32(res, RSA_BASE + RSA_REG_COMMAND)





def demo_rsa():
    # Custom data
    data = bytearray('\x22' + (0x100 - 1) * '\x00')  # 0x22 = 34
    exp = bytearray('\x04' + (0x100 - 1) * '\x00')  # 0x04 = 4
    mod = bytearray('\xff' + (0x100 - 1) * '\x00')  # 0xff = 256

    data_st = rsa_data_struct()
    data_st.data = data

    pub_key = rsa_pub_key_struct()

    pub_key.mod = mod
    pub_key.exp = exp

    t.halt()
    rsa_load(pub_key, data_st)

    result = bytearray(0x100)

    # When we call ioread8 it changes answer
    # for correct answer read byte before result
    # In that case answer will not change
    ioread8(RSA_BASE + 0x200 - 1)
    i = 0
    while i < 0x100:
        result[i] = ioread8(RSA_BASE + 0x200 + i)
        i += 1
    print("Result (little endian):")
    print(''.join(format(x, '02x') for x in result))
