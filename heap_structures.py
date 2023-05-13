##coding=utf-8
import copy

class AllocChunk:
    def __init__(self, addr, size, prim_num, op_index):
        self.addr = addr
        self.size = size
        self.primitive_name = "P"+str(prim_num)
        self.op_index = op_index
    def __str__(self):
        chunks_str = "0x%x--%x--%s--%d"%(self.addr, self.size, self.primitive_name, self.op_index)

    def __hash__(self):
        hash_str = ''
        hash_str += str(self.addr)
        hash_str += str(self.size)
        return hash(hash_str)

    def __eq__(self, new_chunk):
        if not isinstance(new_chunk, AllocChunk):
            return False
        if self.size == new_chunk.size and self.addr == new_chunk.addr:
            return True


class AllocatedChunks:
    """
    A collection of all allocated chunks.
    """
    def __init__(self):
        self.chunks_by_addr = {}
        self.chunks_by_size = {}
        self.chunks_by_primitves= {}

    def __str__(self):
        sorted_address = sorted(self.chunks_by_addr.keys())
        index = 0
        res_str = ''
        for each_addr in sorted_address:
            res_str += '[A] id:%d\t(0x%x, 0x%x)\n' % (index, each_addr, self.chunks_by_addr[each_addr])
            index+= 1
        return res_str[:-1]
        
    def has_chunk(self, addr):
        """
        Check whether chunk at `addr` is in allocated chunks.
        """
        return (addr in self.chunks_by_addr)

    def add_chunk(self, addr, size, primitive_name, op_index):
        """
        Added a chunk into allocated chunks.
        """
        prim_num = int(primitive_name[1:])
        ac = AllocChunk(addr, size, prim_num, op_index)
        self.chunks_by_addr[addr] = size
        if not size in self.chunks_by_size:
            self.chunks_by_size[size] = set()
        self.chunks_by_size[size].add(ac)

    def remove_chunk(self, addr):
        """
        Remove a chunk at `addr` if it is in allocated chunks
        """
        if addr not in self.chunks_by_addr:
            print "chunk at 0x%x is not in allocated!" % addr
            return False

        size = self.chunks_by_addr[addr]
        all_allocated_chunks = copy.deepcopy(self.chunks_by_size)
        for allocated_chunk in all_allocated_chunks[size]:
            if addr == allocated_chunk.addr:
                self.chunks_by_size[size].remove(allocated_chunk)
                break
        del self.chunks_by_addr[addr]
        return True

    def find_lower_addr_chunk(self, addr):
        """
        Find an allocated chunk that locates in adjacent lower address of chunk at `addr`.
        """
        lower_addr = 0x0
        sorted_address = sorted(self.chunks_by_addr.keys())
        for each_addr in sorted_address:
            if each_addr < addr:
                lower_addr = each_addr
            else:
                break
        if lower_addr == 0: # not found
            return [None, None]

        return [lower_addr, self.chunks_by_addr[lower_addr]] # return [addr, size]

    def find_higher_addr_chunk(self, addr):
        """
        Find an allocated chunk that locates in adjacent higher address of chunk at `addr`.
        """
        higher_addr = 0xFFFFFFFFFFFFFFFF
        sorted_address = sorted(self.chunks_by_addr.keys(), reverse=True)
        for each_addr in sorted_address:
            if each_addr > addr:
                higher_addr = each_addr
            else:
                break
        if higher_addr == 0xFFFFFFFFFFFFFFFF: # not found
            return [None, None]

        return [higher_addr, self.chunks_by_addr[higher_addr]] # return [addr, size]

    def get_all_chunks_by_size(self, size):
        """
        Get all chunks that has size `size`
        """
        if size in self.chunks_by_size:
            return self.chunks_by_size[size]

        return []


    def get_num_allocated_chunks(self):
        """
        Get the total number of allocated chunks.
        """
        return len(self.chunks_by_addr)



class FreeList:
    """
    Model the free list in allocators.
    addr : [0x111, 0x222, 0x333, 0x444]
    index: [0,     1,     2,     3]
    Arg:
        chunk_size: the chunk size in this free list
        can_ms    : whether the chunks in free list can Merge/Split, default is False
        is_FILO   : whether the list's behavior is first-in-last-out
    """
    def __init__(self, chunk_size, priority, length_limit = 0, can_ms=False, is_FILO=True):
        self.chunk_size = chunk_size
        self.can_ms = can_ms
        self.is_FILO = is_FILO
        self.chunks = []
        self.priority = priority
        self.length_limit = length_limit

    def __str__(self):
        # sorted_address = sorted(self.chunks)
        index = 0
        if self.can_ms:
            res_str = '--------------------------- FREE SIZE: 0x%x (MS) (P = %d) (IS_FULL=%d)---------------------------\n' % \
                      (self.chunk_size, self.priority, 1 if len(self.chunks) == self.length_limit else 0)
        else:
            res_str = '--------------------------- FREE SIZE: 0x%x   (P = %d)  (IS_FULL=%d)  ---------------------------\n' % \
                      (self.chunk_size, self.priority, 1 if len(self.chunks) == self.length_limit else 0)
        for each_addr in self.chunks:
            res_str += '\t[F] id:%d\t(0x%x, 0x%x)\n' % (index, each_addr, self.chunk_size)
            index+= 1
        return res_str[:-1]


    def add_free_chunk(self, addr):
        """
        Add freed chunk at `addr` into free list.
        """
        self.chunks.append(addr)

    def allocate_one_chunk(self):
        """
        Allcoate one chunk from this free list.
        """
        if len(self.chunks) == 0:
            return [None, None]

        if self.is_FILO:
            return [self.chunks.pop(), self.chunk_size]
        else:
            addr = self.chunks[0]
            del(self.chunks[0])
            return [addr, self.chunk_size]

    def remove_chunk_by_addr(self, addr):
        """
        Remove chunk at `addr` from free list.
        """
        if addr not in self.chunks:
            # print "Chunk at 0x%x is not in this free list" % addr
            return -1

        index = self.chunks.index(addr)
        self.chunks.remove(addr)
        return index

    def remove_chunk_whem_MS(self, addr):
        """
        Remove chunk when merge or splitting.
        Return the index of the target chunk.
        """
        if not self.can_ms:
            print "This free list is not merge/split!"
            return -1

        if addr not in self.chunks:
            print "Chunk at 0x%x is not in this free list" % addr
            return -1

        index = self.chunks.index(addr)
        self.chunks.remove(addr)
        return index

    def find_lower_addr_chunk(self, addr):
        """
        Find an free chunk that locates in adjacent lower address of chunk at `addr` in this free list.
        """
        lower_addr = 0x0
        sorted_address = sorted(self.chunks)
        for each_addr in sorted_address:
            if each_addr < addr:
                lower_addr = each_addr
            else:
                break
        if lower_addr == 0: # not found
            return [None, None]

        return [lower_addr, self.chunk_size] # return [addr, size]

    def find_higher_addr_chunk(self, addr):
        """
        Find an allocated chunk that locates in adjacent higher address of chunk at `addr`.
        """
        higher_addr = 0xFFFFFFFFFFFFFFFF
        sorted_address = sorted(self.chunks, reverse=True)
        for each_addr in sorted_address:
            if each_addr > addr:
                higher_addr = each_addr
            else:
                break
        if higher_addr == 0xFFFFFFFFFFFFFFFF: # not found
            return [None, None]

        return [higher_addr, self.chunk_size] # return [addr, size]

    def find_chunk_position_by_addr(self, addr):
        if addr not in self.chunks:
            return -1

        index = self.chunks.index(addr)
        return index

    def get_num_freed_chunks(self):
        """
        Get the total number of freed chunks in this free list.
        """
        return len(self.chunks)

    def get_ms_permission(self):
        """
        Return True if this free list can merge/split, otherwise False
        """
        return self.can_ms


if __name__ == "__main__":
    ac = AllocatedChunks()
    ac.add_chunk(0x1234, 200)
    ac.add_chunk(0x2234, 200)
    ac.add_chunk(0x3234, 300)
    ac.add_chunk(0x4234, 400)
    ac.add_chunk(0x5234, 500)
    ac.add_chunk(0x6234, 500)
    print ac

    [addr, size] = ac.find_higher_addr_chunk(0x3234)
    print "addr = 0x%x" % addr

    fl = FreeList(300, can_ms=True, is_FILO=True)
    fl.add_free_chunk(0x123)
    fl.add_free_chunk(0x223)
    fl.add_free_chunk(0x323)
    fl.add_free_chunk(0x423)
    print fl

    [addr, size] = fl.allocate_one_chunk()
    print "addr = 0x%x" % addr

    index = fl.remove_chunk_whem_MS(0x223)
    print "index = %d" % index



