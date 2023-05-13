#coding=utf-8
class Operation:
    def __init__(self):
        self.pname = ''
        self.pnum = -1
        self.op_type = 'M'
        self.op_index = -1
        self.interesting_for_split = 0

        ## malloc
        self.malloc_size = -1
        self.malloc_target = None
        self.malloc_taint = True
        self.malloc_chunk_addr = -1


        ## free
        self.free_target = None
        self.free_malloc_index = -1
        self.free_chunk_size = -1
        self.free_chunk_addr = -1

    def __str__(self):
        x = ''
        if self.op_type == 'M':
            x += 'm('
            x += str(self.malloc_size)
            x += ')'
        else:
            x += 'f('
            x += str(self.free_target)
            x += ', '
            x += str(self.free_malloc_index)
            x += ','
            x += str(self.free_chunk_size)
            x += ','
            x += str(self.free_chunk_addr)
            x += ')'
        return x


class Primitive:
    def __init__(self):
        self.operation_list = []
        self.operation_len = 0
        self.prim_name = None

    def __str__(self):
        x = ''
        for each_op in self.operation_list:
            x += str(each_op)
            x += " --> "
        return x

    def get_str_primitve(self):
        prim_str = self.__str__()
        return  prim_str

    def add_operation(self, op):
        self.operation_list.append(op)
        self.operation_len += 1

    def del_operation(self, op):
        if op not in self.operation_list:
            return
        self.operation_list.remove(op)
        self.operation_len -= 1


