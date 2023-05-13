from run_config import SYSTEM_BIT

if SYSTEM_BIT == "32":

    # MIN_CHUNK_SIZE = 0x20
    MIN_CHUNK_SIZE = 0x10
    MAX_CHUNK_SIZE = 0x2fff0
    # MS_START_SIZE  = 0x400
    MS_START_SIZE  = 0x100
    SIZE_SZ        = 4
    HAS_TCACHE     = True
    MS_INDEX = 1
    MALLOC_SIZE_OPTIONS = [x for x in range(MIN_CHUNK_SIZE, 0x2ff0, 2*SIZE_SZ)]
    LENGTH_LIMIT = 7

elif SYSTEM_BIT == "64":
    MIN_CHUNK_SIZE = 0x20
    MAX_CHUNK_SIZE = 0x2fff0
    MS_START_SIZE  = 0x100
    SIZE_SZ        = 8
    HAS_TCACHE     = True
    MS_INDEX = 1
    MALLOC_SIZE_OPTIONS = [x for x in range(MIN_CHUNK_SIZE, 0x2ff0, 2*SIZE_SZ)]
    LENGTH_LIMIT = 7