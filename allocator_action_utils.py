from layout import Layout


class ComplexActorUtil:
    def __init__(self):
        pass

    @staticmethod
    def merge_lower_chunk(layout, cur_addr, cur_size, lower_addr, lower_size):
        """
        Merge current chunk with lower chunk.
        """
        if not isinstance(layout, Layout):
            print "Check your layout parameter!"
            return False
        
        if not layout.allocated_chunks.has_chunk(cur_addr):
            print "Current chunk at 0x%x is not allocated chunk!" % cur_addr
            return False

        # 1st: remove cur_addr from allocated chunks
        layout.remove_chunk_from_allocated_chunks(cur_addr)

        # 2nd: remove lower_addr from free list
        layout.remove_chunk_when_merging_or_splitting(lower_addr, lower_size)

        # 3rd: insert new free chunk into free list
        new_chunk_addr = lower_addr
        new_chunk_size = cur_size + lower_size
        layout.add_free_chunk(new_chunk_addr, new_chunk_size)

        return True

    @staticmethod
    def merge_higher_chunk(layout, cur_addr, cur_size, higher_addr, higher_size):
        """
        Merge current chunk with higher chunk.
        """
        if not isinstance(layout, Layout):
            print "Check your layout parameter!"
            return False
        
        if not layout.allocated_chunks.has_chunk(cur_addr):
            print "Current chunk at 0x%x is not allocated chunk!" % cur_addr
            return False

        # 1st: remove cur_addr from allocated chunks
        layout.remove_chunk_from_allocated_chunks(cur_addr)

        # 2nd: remove higher_addr from free list
        layout.remove_chunk_when_merging_or_splitting(higher_addr, higher_size)

        # 3rd: insert new free chunk into free list
        new_chunk_addr = cur_addr
        new_chunk_size = cur_size + higher_size
        layout.add_free_chunk(new_chunk_addr, new_chunk_size)

        return True

    @staticmethod
    def merge_lower_and_higher_chunk(layout, cur_addr, cur_size,
                                                    lower_addr, lower_size,
                                                    higher_addr, higher_size):
        """
        Merge current chunk with lower chunk and higher chunk.
        """
        if not isinstance(layout, Layout):
            print "Check your layout parameter!"
            return False
        
        if not layout.allocated_chunks.has_chunk(cur_addr):
            print "Current chunk at 0x%x is not allocated chunk!" % cur_addr
            return False

        # 1st: remove cur_addr from allocated chunks
        layout.remove_chunk_from_allocated_chunks(cur_addr)

        # 2nd: remove lower_addr from free list
        layout.remove_chunk_when_merging_or_splitting(lower_addr, higher_size)

        # 3rd: remove higher_addr from free list
        layout.remove_chunk_when_merging_or_splitting(higher_addr, higher_size)

        # 4th: insert new free chunk into free list
        new_chunk_addr = lower_addr
        new_chunk_size = cur_size + lower_size + higher_size
        layout.add_free_chunk(new_chunk_addr, new_chunk_size)

        return True

    @staticmethod
    def split_chunk(layout, cur_addr, cur_size, split_size):
        """
        Split chunk with split size.
        """
        if not isinstance(layout, Layout):
            print "Check your layout parameter!"
            return False

        # 1st: remove this free chunk from free list
        layout.remove_chunk_when_merging_or_splitting(cur_addr, cur_size)

        # 2nd: add new chunk to allocated chunks
        new_chunk_addr = cur_addr
        new_chunk_size = split_size
        layout.add_allocated_chunk(new_chunk_addr, new_chunk_size)

        # 3rd: insert remained to free list
        remain_chunk_addr = cur_addr + split_size
        remain_chunk_size = cur_size - split_size
        layout.add_free_chunk(remain_chunk_addr, remain_chunk_size)

        return True

    @staticmethod
    def cut_from_top_chunk(layout, cut_size):
        """
        Cut `cut_size` from top chunk.
        """
        if not isinstance(layout, Layout):
            print "Check your layout parameter!"
            return False

        # 1st: add new chunk into allocated chunks
        new_chunk_addr = layout.top_chunk
        new_chunk_size = cut_size
        layout.add_allocated_chunk(new_chunk_addr, new_chunk_size)

        # 2nd: increase top chunk
        layout.top_chunk += cut_size

        return True

    @staticmethod
    def merge_into_top_chunk(layout, cur_addr, cur_size):
        """
        Merge current chunk into top chunk.
        """
        if not isinstance(layout, Layout):
            print "Check your layout parameter!"
            return False

        if not layout.allocated_chunks.has_chunk(cur_addr):
            print "Current chunk at 0x%x is not allocated chunk!" % cur_addr
            return False

        # 1st: remove cur_addr from allocated chunks
        layout.remove_chunk_from_allocated_chunks(cur_addr)

        # 2nd: decrease top chunk to cur_addr
        layout.top_chunk = cur_addr

    @staticmethod
    def merge_lower_chunk_to_top_chunk(layout, cur_addr, cur_size, lower_addr, lower_size):
        """
        Merge current chunk with lower chunk.
        """
        if not isinstance(layout, Layout):
            print "Check your layout parameter!"
            return False
        
        if not layout.allocated_chunks.has_chunk(cur_addr):
            print "Current chunk at 0x%x is not allocated chunk!" % cur_addr
            return False

        # 1st: remove cur_addr from allocated chunks
        layout.remove_chunk_from_allocated_chunks(cur_addr)

        # 2nd: remove lower_addr from free list
        layout.remove_chunk_when_merging_or_splitting(lower_addr, lower_size)

        # 3rd: decrease top chunk to lower_addr
        layout.top_chunk = lower_addr

        return True

    @staticmethod
    def update_layout_by_effects(layout, effects):
        """
        Update layout by effects.
        effects: {'A': [[12, 0xaaa, +1], [24, 0xbbb, -1]], 'F': [[12, 0xccc, +1]]}
        """
        for action in effects:
            if action == 'A':
                for [size, addr, eff, primitive_name, op_index] in effects[action]:
                    if eff == -1:
                        if not layout.allocated_chunks.has_chunk(addr):
                            continue
                        layout.remove_chunk_from_allocated_chunks(addr)
                    elif eff == 1:
                        layout.add_allocated_chunk(addr, size, primitive_name, op_index)
                    else:
                        pass

            elif action == 'F':
                for [size, addr, eff, primitive_name, op_index] in effects[action]:
                    if eff == 1:
                        layout.add_free_chunk(addr, size)
                    elif eff == -1:
                        layout.remove_chunk_from_free_list(addr, size)
                    else:
                        pass
            elif action == 'T':
                for [size, addr, eff, primitive_name, op_index] in effects[action]:
                    layout.update_top_chunk(size, eff)
            else:
                continue  # ignore illegal action

        return
