#coding=utf-8

import os
import json
from collections import OrderedDict
from primitive import *

class PrimitiveDumper:
    def __init__(self, primitives, ppath):
        self.ppath = ppath
        self.primitives = primitives

    def dump_primitive(self):
        pinfo = {'total_primitives': len(self.primitives)}
        for pname in self.primitives:
            prim_dump_info = {}
            prim_dump_info['num_operations'] = len(self.primitives[pname].operation_list)
            for index in range(0, len(self.primitives[pname].operation_list)):
                oname = "o%d" % index
                prim_dump_info[oname] = {}
                op = self.primitives[pname].operation_list[index]
                prim_dump_info[oname]['pnum'] = op.pnum
                prim_dump_info[oname]['op_index'] = op.op_index
                if op.op_type == 'M':
                    prim_dump_info[oname]['type'] = 'M'
                    prim_dump_info[oname]['size'] = op.malloc_size
                else:
                    prim_dump_info[oname]['type'] = 'F'
                    prim_dump_info[oname]['target'] = op.free_target
                    prim_dump_info[oname]['index'] = op.free_malloc_index
            pinfo[pname] = prim_dump_info

        with open(self.ppath, 'w') as f:
            f.write(json.dumps(pinfo, indent=4, sort_keys=True))


class PrimitiveFetcher:
    def __init__(self, ppath):
        self.ppath = ppath

    def fetch_primitive(self):
        all_primitives = OrderedDict()
        if not os.path.isfile(self.ppath):
            print "Cannot find primitive json file at %s" % self.ppath
            return all_primitives

        try:
            pinfo = json.load(open(self.ppath, 'r'))
        except Exception as e:
            print "Failed to load primitive file at %s as json" % self.ppath
            print "Error is: " + str(e)
            return all_primitives

        total_number = pinfo['total_primitives']
        for pindex in range(0, total_number):
            pname = "P" + str(pindex)
            cur_pinfo = pinfo[pname]
            onum = cur_pinfo['num_operations']

            cur_prim = Primitive()
            cur_prim.prim_name = pname

            # print "========== %s ==============" % pname
            for oindex in range(0, onum):
                oname = "o"+ str(oindex)
                cur_oinfo = cur_pinfo[oname]
                
                cur_op = Operation()
                cur_op.op_type = cur_oinfo['type']
                cur_op.op_index = cur_oinfo['op_index']
                cur_op.pnum = cur_oinfo['pnum']
                cur_op.pname = pname

                if cur_op.op_type == 'M':
                    cur_op.malloc_size = cur_oinfo['size']
                    cur_op.malloc_target = pname
                    cur_op.malloc_taint = (cur_op.malloc_size == -1)

                else:
                    cur_op.free_target = cur_oinfo['target']
                    cur_op.free_malloc_index = cur_oinfo['index']


                cur_prim.add_operation(cur_op)

            all_primitives[pname] = cur_prim

        return all_primitives

    def fetch_count_dependency(self):

        prims_count_dependecy = OrderedDict()

        if not os.path.isfile(self.ppath):
            print "Cannot find primitive count dependency json file at %s" % self.ppath
            return prims_count_dependecy

        try:
            pinfo = json.load(open(self.ppath, 'r'))
        except Exception as e:
            print "Failed to load primitive count dependency file at %s as json" % self.ppath
            print "Error is: " + str(e)
            return prims_count_dependecy

        for each_item in pinfo.keys():
            prims_count_dependecy[each_item] = pinfo[each_item]

        return prims_count_dependecy





