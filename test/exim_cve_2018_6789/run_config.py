
# test exim cve-2018-6789
P_FILE_PATH = "/home/usera/Heap_Layout/test/exim_cve_2018_6789/ps.json"
INIT_LAYOUT_PATH = "/home/usera/Heap_Layout/test/exim_cve_2018_6789/layout"
BASE_OP_LIST_PATH = ""
TARGET_CHUNK_ADDR = 0x55f7e07e1a20
TARGET_HOLE_SIZE = 0x2020
TARGET_PRIM_NAME = "P5"
TARGET_OP_INDEX = 0
SYSTEM_BIT = "64"
MULTI_TARGETS = [[0x55f7e07e1a20, 0x30], [0x55f7e07e1a50, 0x2020], [0x55f7e07e3a70, 0x2c10]]
ORIGINAL_FREE_CHUNK = [TARGET_CHUNK_ADDR, 0x6060]
TIMES_LIMITATION = {"P0":1, "P1":1, "P2":1, "P3":1, "P4":0, "P5":1 , "P6":1 , "P7":1 , "P8":1, "P9":1}