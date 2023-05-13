from z3 import *
import itertools
import pickle
from dump_and_fetch_primitive import PrimitiveFetcher
from layout import Layout

def calculate_two_lists(list_1, list_2):
    res_list = []
    for item in itertools.product(list_1,list_2):
        res_list.append(str(item[0])+','+str(item[1]))
    return res_list

def get_all_primitives_from_files(p_file_path):
    pf = PrimitiveFetcher(p_file_path)
    all_prims = pf.fetch_primitive()
    return all_prims


def get_primitives_count_dependency(p_file_path):
    pf = PrimitiveFetcher(p_file_path)
    prims_count_dependency = pf.fetch_count_dependency()
    return prims_count_dependency



def calculate_sum_of_list(abi_list):
    sum = 0
    for abi in abi_list:
        sum += abi
    return sum

def get_heap_layout_from_file(init_file):
    heap_layout = Layout()
    heap_layout.parse_layout_from_file(init_file)
    return heap_layout


def calculate_target_distance_by_chunk(chunk_size, chunk_addr, init_file):

    heap_layout = get_heap_layout_from_file(init_file)
    free_lists = heap_layout.get_free_lists()
    count_distance = 0
    for priority in range(0, len(free_lists[chunk_size])):
        fl = free_lists[chunk_size][priority]
        if chunk_addr in fl.chunks:
            count_distance += len(fl.chunks) - fl.chunks.index(chunk_addr) - 1
            break
        else:
            count_distance = len(fl.chunks)
    return 0 - count_distance


def dump_final_op_list(layout_file, op_file_name, origin_op_list):
    '''
    to find the free malloc index for free op and generate final op list
    :param layout_file:
    :param origin_op_list: (need to determine the free malloc index for each free op)
    :return: final op list
    '''

    if not os.path.isfile(layout_file):
        print "Cannot find layout file at %s" % layout_file
        return False

    allocated_chunks_list = []
    find_free_op = False
    already_index_list = []

    with open(layout_file, "r") as f:
        for line in f.readlines():
            line = line.rstrip('\n')
            [chunk_type, addr_str, size_str, p_num_str, op_index, alloc_index] = line.split('|')
            addr = int(addr_str, 16)
            size = int(size_str, 16)
            op_index = int(op_index)
            alloc_index = int(alloc_index)
            if chunk_type == 'A':
                primitive_name = "P" + p_num_str
                allocated_chunks_list.append([addr, size, primitive_name, op_index, alloc_index])
            else:
                continue
    if op_file_name == "":
        already_base_op_list =[]
    else:
        if not os.path.isfile(op_file_name):
            print ("Base layout operation list file at %s is not found!" % op_file_name)
            return False

        try:
            with open(op_file_name, 'rb') as f:
                already_base_op_list = pickle.load(f)
        except Exception as e:
            print ("Failed to load file at %s as pickle file" % op_file_name)
            print ("Error is " + str(e))
            return False

    count_malloc_op = 0
    for each_op in already_base_op_list:
        if each_op.op_type == "M":
            count_malloc_op += 1
        else:
            already_index_list.append(each_op.free_malloc_index)



    malloc_op_list = []
    free_op_list = []

    for op in origin_op_list:
        if op.op_type == "M":
            malloc_op_list.append(op)
        elif op.op_type == "F":
            op.free_malloc_index = -1
            free_op_list.append(op)



    ## find the free op which free malloc index is already determined
    for each_op in free_op_list:
            if each_op.free_malloc_index > 10:
                already_index_list.append(each_op.free_malloc_index)

    ## determine the free_malloc_index for the undetermined free op
    for each_op in free_op_list:
            ## find the free op in layout file
            if each_op.free_malloc_index not in already_index_list:
                for malloc_index, chunk in enumerate(allocated_chunks_list):
                    if chunk[0] == each_op.free_chunk_addr and chunk[-1] not in already_index_list:
                        each_op.free_malloc_index = chunk[-1]
                        already_index_list.append(chunk[-1])
                        find_free_op = True
                        break

            ## find the free op in original op list
            if each_op.free_malloc_index == -1:
                for malloc_index, each_malloc_op in enumerate(malloc_op_list):
                        if each_malloc_op.malloc_chunk_addr == each_op.free_chunk_addr and (count_malloc_op + malloc_index) not in already_index_list:
                            each_op.free_malloc_index = count_malloc_op + malloc_index
                            already_index_list.append(len(allocated_chunks_list) + malloc_index)
                            find_free_op = True
                            break

    if not find_free_op and len(free_op_list) > 0:
        print "wrong, can not determine free malloc op index in final op list"
        return []

    return origin_op_list




