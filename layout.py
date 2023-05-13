import copy
import json
import os
from heap_structures import AllocatedChunks, FreeList
from allocator_config import *

class Layout:
    """
    Model the heap layout.
    """
    def __init__(self):
        self.min_chunk_size = MIN_CHUNK_SIZE
        self.max_chunk_size = MAX_CHUNK_SIZE
        self.ms_start_size = MS_START_SIZE 
        self.size_sz = SIZE_SZ
        self.has_tcache = HAS_TCACHE
        self.top_chunk = 0x0
        if self.has_tcache:
            self.priority_num = [0, 1]
        else:
            self.priority_num = [0]
        # initialize allocated chunks and free lists
        self.allocated_chunks = AllocatedChunks()
        self.malloc_size_opitons = []
        self.free_lists = {}

        for size in range(self.min_chunk_size, self.max_chunk_size+ 2*self.size_sz, 2*self.size_sz):
            can_ms = False
            self.free_lists[size] = []
            for priority in self.priority_num:
                is_FILO = False
                if priority < MS_INDEX:
                    can_ms = False
                    length_limit = LENGTH_LIMIT
                    is_FILO = True
                else:
                    if size >= self.ms_start_size:
                        can_ms = True
                        is_FILO = False
                    else:
                        can_ms = False
                        is_FILO = True
                    length_limit = 999999
                cur_fl = FreeList(size, priority, length_limit, can_ms=can_ms, is_FILO=is_FILO)
                self.free_lists[size].append(cur_fl)
            self.malloc_size_opitons.append(size)

    def get_malloc_size_options(self):
        return self.malloc_size_opitons

    def parse_layout_from_file(self, file_name):
        """
        File content format:
        A|12345|100
        F|12345|200
        F|22345|200
        NOTE: free chunks MUST be in order.
        """
        if not os.path.isfile(file_name):
            print "Cannot find layout file at %s" % file_name
            return False

        with open(file_name, "r") as f:
            for line in f.readlines():
                line = line.rstrip('\n')
                [chunk_type, addr_str, size_str, p_num_str, op_index, alloc_index] = line.split('|')
                addr = int(addr_str, 16)
                size = int(size_str, 16)
                op_index = int(op_index)
                if chunk_type == 'A':
                    primitive_name = "P"+p_num_str
                    self.add_allocated_chunk(addr, size, primitive_name, op_index)
                elif chunk_type == 'F' or chunk_type == 'C' or chunk_type == "R" or chunk_type == "U":
                    self.init_free_chunk(chunk_type, addr, size)
                elif chunk_type == 'T':
                    self.top_chunk = addr
                else:
                    continue
        return

    # ------------------- top chunk operation ------------------------------#

    def update_top_chunk(self, size, eff):
        if eff > 0:
            self.top_chunk = self.top_chunk - size
        if eff < 0:
            self.top_chunk = self.top_chunk + size

    #-------------------- allocated chunks operations -----------------------#

    def add_allocated_chunk(self, addr, size, primitive_name, op_index):
        """
        Add chunk at `addr` to allocated chunks.
        """
        self.allocated_chunks.add_chunk(addr, size, primitive_name, op_index)

    def remove_chunk_from_allocated_chunks(self, addr):
        """
        Remove chunk at `addr` to allocated chunks.
        """
        return self.allocated_chunks.remove_chunk(addr)

    def get_allocated_chunks(self):
        """
        Return all allocated chunks by size as key.
        """
        return self.allocated_chunks.chunks_by_size

    #-------------------- free list operations -------------------------#

    def get_free_lists(self):
        """
        Return all free chunks by size as key.
        """
        all_free_chunks = {}
        for each_size in self.free_lists:
            all_free_chunks[each_size] = []
            for priority in self.priority_num:
                fl = self.free_lists[each_size][priority]
                if fl.get_num_freed_chunks() == 0:
                    continue
                # all_free_chunks[each_size].append(fl.chunks)
                all_free_chunks[each_size].append(fl)
        return all_free_chunks

    def add_free_chunk(self, addr, size):
        """
        Add freed chunk in to free list with size.
        """
        if size > MS_START_SIZE:
            fl = self.free_lists[size][-1]
            fl.add_free_chunk(addr)
        else:
            for priority in self.priority_num:
                fl = self.free_lists[size][priority]
                if priority < MS_INDEX:
                    if fl.get_num_freed_chunks() < fl.length_limit:
                        fl.add_free_chunk(addr)
                        break
                    elif fl.get_num_freed_chunks() == fl.length_limit:
                        continue
                else:
                    fl.add_free_chunk(addr)

    def init_free_chunk(self, chunk_type, addr, size):
        """
        Add freed chunk in to free list with size.
        """

        if chunk_type == 'C':
            priority = self.priority_num[0]
            fl = self.free_lists[size][priority]
            if fl.get_num_freed_chunks() < fl.length_limit:
                fl.add_free_chunk(addr)
            elif fl.get_num_freed_chunks() == fl.length_limit:
                return None

        elif chunk_type == 'F' or chunk_type == "R" or chunk_type == "U":
            priority = self.priority_num[-1]
            fl = self.free_lists[size][priority]
            fl.add_free_chunk(addr)


    def allocate_one_chunk_from_list(self, size):
        """
        Allcoate one chunk from free lists.
        Return [addr, size]
        """
        for priority in self.priority_num:
            [addr, chunk_size] = self.free_lists[size][priority].allocate_one_chunk()
            if addr is not None:
                return [addr, chunk_size]
            else:
                continue

        return [addr, chunk_size]

    def remove_chunk_from_free_list(self, addr, size):
        """
        Remove specific chunk from free list.
        """
        found_prio = -1
        found_re_index = -1
        for priority in self.priority_num:
            re_index = self.free_lists[size][priority].remove_chunk_by_addr(addr)
            if re_index >= 0:
                found_prio = priority
                found_re_index = re_index
                break
            else:
                continue
        if found_re_index < 0:
            print "Chunk at 0x%x is not in this free list" % addr
            return found_re_index

        if found_prio > 0:  # malloc a chunk from normal free list not tcache
            self.try_move_chunks_from_lower_to_higher_priority(size, found_prio)

        return found_re_index

    def try_move_chunks_from_lower_to_higher_priority(self, size, cur_priority):
        """
        Move fast bins/ small bins to tcache.
        Remember the priority order: higher <-- [0, 1, 2, 3, 4]  --> lower
        """
        if cur_priority == 0:
            return
        if self.free_lists[size][cur_priority - 1].get_num_freed_chunks() != 0:  # impossible
            return

        remained_chunks = copy.deepcopy(self.free_lists[size][cur_priority].chunks)
        added = 0
        if self.free_lists[size][cur_priority].is_FILO:
            remained_chunks.reverse()

        for addr in remained_chunks:
            self.free_lists[size][cur_priority - 1].add_free_chunk(addr)
            self.free_lists[size][cur_priority].remove_chunk_by_addr(addr)
            added += 1
            if added == self.free_lists[size][cur_priority - 1].length_limit:
                break
        return

    def get_distance_to_target_hole(self, addr, size):
        """
        Get how many standard dig operations to target hole.
        Args:
            addr: the address of target hole
            size: the size of target hole

        Returns:
            The distance to target hole. Return -1 if target hole is not found.
        """
        found_chunk = False
        found_prio = -1
        found_re_index = -1
        for priority in self.priority_num:
            re_index = self.free_lists[size][priority].find_chunk_position_by_addr(addr)
            if re_index < 0:  # not found
                continue
            else:
                found_chunk = True
                found_prio = priority
                found_re_index = re_index
                break

        if not found_chunk:
            return -1

        if found_prio == 0:  # if target chunk in tcache, just return.
            if self.free_lists[size][found_prio].is_FILO:
                distance = self.free_lists[size][found_prio].get_num_freed_chunks() - found_re_index
            else:
                distance = found_re_index + 1
            return distance


        distance = self.free_lists[size][found_prio - 1].get_num_freed_chunks()

        # construct a new order
        tmp_chunks = copy.deepcopy(self.free_lists[size][found_prio].chunks)
        if self.free_lists[size][found_prio].is_FILO:
            tmp_chunks.reverse()
        new_orders = []

        higher_limit = self.free_lists[size][found_prio - 1].length_limit
        index = 0
        while index < len(tmp_chunks):
            if index + (higher_limit + 1) < len(self.free_lists[size][found_prio].chunks):
                new_orders.append(index)
                for delta in range(0, higher_limit):
                    new_orders.append(index + higher_limit - delta)
                index += (higher_limit + 1)
            else:
                new_orders.append(index)
                remained_order = []
                index += 1
                for remained_index in range(index, len(self.free_lists[size][found_prio].chunks)):
                    remained_order.append(remained_index)
                new_orders += reversed(remained_order)
                break

        for each_index in new_orders:
            if tmp_chunks[each_index] == addr:
                distance += 1
                break
            distance += 1

        return distance

    def get_can_ms_free_chunks(self):
        """
        Get all free chunks that can be splitted or merged.
        """
        all_ms_free_chunks = {}
        for each_size in self.free_lists:
            for priority in self.priority_num:
                if priority >= MS_INDEX:
                    fl = self.free_lists[each_size][priority]
                    if fl.get_num_freed_chunks() == 0:
                        continue
                    if not fl.can_ms:
                        continue
                    # all_ms_free_chunks[each_size] = fl.chunks
                    all_ms_free_chunks[each_size] = fl
                else:
                    continue

        return all_ms_free_chunks


    #--------------------- universal interfaces -------------------------#

    def check_ms_permission(self, addr, size, index):
        """
        Check whether the chunk at `addr` can be merged or splitted.
        """
        if self.allocated_chunks.has_chunk(addr):
            print "Chunk at 0x%x is an allocatd chunk!" % addr
            return False

        if not self.free_lists[size][index].has_chunk(addr):
            print "Chunk at 0x%x is not in free list!" % addr
            return False

        return self.free_lists[size][index].get_ms_permission()

    def check_ms_permission_ignore_chunk_status(self, addr, size, index):
        """
        Check whether the chunk at `addr` can be merged or splitted but ignore the chunk status.
        """
        return self.free_lists[size][index].get_ms_permission()


    def get_lower_chunk_information(self, addr, index):
        """
        Get lower chunk information.
        Return [addr, size, type] : type is 1 if allocated otherwise 0
        """
        lowers = {}
        [lower_alloc_addr, lower_alloc_size] = self.allocated_chunks.find_lower_addr_chunk(addr)
        if lower_alloc_addr is not None:
            lowers[lower_alloc_addr] = [lower_alloc_size, 1]

        for each_size in self.free_lists:
            [lower_free_addr, lower_free_size] = self.free_lists[each_size][index].find_lower_addr_chunk(addr)
            if lower_free_addr is not None:
                lowers[lower_free_addr] = [lower_free_size, 0]

        if len(lowers) == 0:
            return [None, None, None]

        sorted_address = sorted(lowers)
        max_lower_addr = sorted_address[-1]
        return [max_lower_addr, lowers[max_lower_addr][0], lowers[max_lower_addr][1]]

    def get_higher_chunk_information(self, addr, index):
        """
        Get higher chunk information.
        Return [addr, size, type] : type is 1 if allocated otherwise 0
        """
        highers = {}
        [higher_alloc_addr, higher_alloc_size] = self.allocated_chunks.find_higher_addr_chunk(addr)
        if higher_alloc_addr is not None:
            highers[higher_alloc_addr] = [higher_alloc_size, 1]

        for each_size in self.free_lists:
            [higher_free_addr, higher_free_size] = self.free_lists[each_size][index].find_higher_addr_chunk(addr)
            if higher_free_addr is not None:
                highers[higher_free_addr] = [higher_free_size, 0]

        if len(highers) == 0:
            return [None, None, None]

        sorted_address = sorted(highers)
        min_higher_addr = sorted_address[0]
        return [min_higher_addr, highers[min_higher_addr][0], highers[min_higher_addr][1]]


    def remove_chunk_when_merging_or_splitting(self, addr, size, index):
        """
        Remove chunk when merging or splitting from free list.
        """
        self.free_lists[size][index].remove_chunk_whem_MS(addr)

    def dump_layout(self):
        print "======================== Allocated Chunks ================================="
        print self.allocated_chunks

        print "========================= Free List ======================================="
        for each_size in self.free_lists:
            for priority in self.priority_num:
                if self.free_lists[each_size][priority].get_num_freed_chunks() == 0:
                    continue
                print self.free_lists[each_size][priority]

        print "Top chunk is at 0x%x" % self.top_chunk

    def dump_heap_layout_to_json(self, filename):
        heap_layout = dict()
        heap_layout["chunks"] = []

        top_chunk = self.top_chunk

        for each_addr in self.allocated_chunks.chunks_by_addr:
            item = {}
            item["addr"] = each_addr
            item["size"] = self.allocated_chunks.chunks_by_addr[each_addr]
            item["type"] = "A"
            heap_layout["chunks"].append(item)
        for each_size in self.free_lists:
            for priority in self.priority_num:
                if self.free_lists[each_size][priority].get_num_freed_chunks() == 0:
                    continue
                else:
                    fl = self.free_lists[each_size][priority]
                    for each_addr in fl.chunks:
                        fl_chunk = {}
                        fl_chunk["addr"] = each_addr
                        fl_chunk["size"] = each_size
                        fl_chunk["type"] = "F"
                        heap_layout["chunks"].append(fl_chunk)

        with open(filename, "w") as f:
            json.dump(heap_layout, f)


if __name__ == "__main__":
    layout = Layout()
    layout.parse_layout_from_file('/home/usera/testheap/layout.txt')

    layout.dump_layout()
    print layout.get_distance_to_target_hole(0x555555559390, 0x20)
