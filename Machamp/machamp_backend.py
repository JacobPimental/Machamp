import r2pipe
import hashlib
import codecs
import argparse
import yaml
import fnmatch
import machamp_utils

class Machamp:
    def __init__(self, flags=[], filename=None):
       self.utils = machamp_utils.MachampUtils(flags, filename)

    def get_basic_block_id(self, addr, bb):
        if bb == None:
            return -1
        for i in range(len(bb)):
            block = bb[i]
            if block['addr'] == addr:
                return i
        return -1

    def get_basic_block_types(self, disas):
        types = {'call': 0,
                 'logical': 0,
                 'arithmetic': 0}
        if disas:
            for d in disas:
                if 'type' in d.keys():
                    t = d['type']
                    if t == 'call':
                        types['call'] += 1
                    elif t in ['and', 'not', 'or', 'xor']:
                        types['logical'] += 1
                    elif t in ['inc','dec','add','sub',
                               'mul','imul','div','idiv']:
                        types['arithmetic'] += 1
        return types

    def form_machamp_block_string(self, index, bb, ins):
        block = bb[index]
        fail = (-1 if 'fail' not in block.keys()
                else self.get_basic_block_id(block['fail'], bb))
        jump = (-1 if 'jump' not in block.keys()
                else self.get_basic_block_id(block['jump'], bb))
        if index == 0:
            start = 0
        else:
            start = bb[index-1]['ninstr']
        end = block['ninstr'] - 1
        types = self.get_basic_block_types(ins['ops'][start:end])
        string = '{}:j{};f{};c{};l{};a{}'.format(index, jump, fail, types['call'],
                                                 types['logical'],
                                                 types['arithmetic'])
        return bytes(string, 'UTF-8')

    def form_machamp_function_string(self, func_info):
        f = func_info
        nargs = (-1 if 'nargs' not in f.keys()
                 else f['nargs'])
        nlocals = (-1 if 'nlocals' not in f.keys()
                   else f['nlocals'])
        string = '{}:{}'.format(nargs, nlocals)
        return bytes(string, 'UTF-8')

    def form_machamp_hash(self, data):
        basic_blocks = data['bb']
        machamp_hash = ''
        for i in range(len(basic_blocks)):
            m_string = self.form_machamp_block_string(i, basic_blocks,
                                                      data['ins'])
            m_hash = hashlib.md5(m_string)
            mb64 = codecs.encode(m_hash.digest(), 'base64')[:6]
            machamp_hash += mb64.decode('UTF-8')
        f_string = self.form_machamp_function_string(data['func_info'])
        f_hash = hashlib.md5(f_string)
        fb64 = codecs.encode(f_hash.digest(), 'base64')[:6]
        machamp_hash += fb64.decode('UTF-8')
        return machamp_hash

    def form_machamp_table(self, exclude=[], analyze_level='aaa', quiet=False):
        if not quiet: print('Running {} first, this may take a while...'.format(analyze_level))
        self.utils.analyze_binary(analyze_level)
        if not quiet: print('Removing any overlapping functions...')
        self.utils.remove_overlapping_functions()
        if not quiet: print('Generating Machamp table...')
        table = {}
        funcs = self.utils.get_function_info()
        funcs = self.remove_excluded_functions(funcs, exclude)
        func_dat = []
        print('Analyzing {} funcs'.format(len(funcs)))
        for f in funcs:
            func_dat.append(self.generate_necessary_machamp_data(f))

        table = {f['name']: self.form_machamp_hash(f) for f in func_dat if
                 self.form_machamp_hash(f)}
        return table

    def generate_necessary_machamp_data(self, func):
        fname = func['name']
        bb = self.utils.get_basic_block_info(fname)
        ins = self.utils.get_function_instructions(fname)
        return {'bb':bb, 'ins':ins, 'func_info':func, 'name':fname}

    def remove_excluded_functions(self, funcs, patterns):
        fnames = [f['name'] for f in funcs]
        for p in patterns:
            fnames = [n for n in fnames if n not in fnmatch.filter(fnames, p)]
        flist = [f for f in funcs if f['name'] in fnames]
        return flist

    def is_in_exclude(self, string, patterns):
        for p in patterns:
            if fnmatch.fnmatch(string, p):
                return True
        return False

    def output_machamp_table(self, t, filename):
        f = open(filename, 'w')
        yaml.dump(t, f)
        f.close()

    def read_machamp_file(self, filename):
        f = open(filename, 'r')
        try:
            t = yaml.safe_load(f)
            f.close()
            return t
        except yaml.YAMLError as e:
            print(e)
            f.close()
            return {}


    def machamp_compare(self, a, b):
        if len(a) < len(b):
            a += '-'*(len(b)-len(a))
        elif len(b) < len(a):
            b += '-'*(len(a)-len(b))
        same = sum( a[i] == b[i] for i in range(len(a)) )
        percent = (same / len(a))*100
        return percent

    def get_most_likely_function(self, m_hash, table):
        highest = 0
        most_likely = ''
        for k in table.keys():
            h = table[k]
            c = self.machamp_compare(m_hash, h)
            if c > highest:
                highest = c
                most_likely = k
        return most_likely, highest

    def rename_functions(self, **kwargs):
        if not 'compare_to' in kwargs.keys():
            print('Need a table to compare to')
            return

        t2 = kwargs['compare_to']

        if not 'exclude' in kwargs.keys():
            exclude = []
        else:
            exclude = kwargs['exclude']

        if not 'machamp_table' in kwargs.keys():
            t1 = self.form_machamp_table(exclude)
        else:
            t1 = kwargs['machamp_table']

        if not 'threshold' in kwargs.keys():
            threshold = 80
        else:
            threshold = kwargs['threshold']

        fcn_renames = self.get_function_renames(t1, t2, exclude, threshold)
        for f in fcn_renames.keys():
            orig = fcn_renames[f]['fcn']
            self.utils.rename_function(f, orig)
        return fcn_renames

    def get_function_renames(self, t1, t2, exclude=[], threshold=80):
        renames = {}
        for k in t1:
            if not self.is_in_exclude(k, exclude):
                most_likely, percent = self.get_most_likely_function(t1[k], t2)
                if not most_likely in renames.keys() and percent >= threshold:
                    renames[most_likely] = {'fcn':k, 'percent':percent}
                elif percent >= threshold and percent > renames[most_likely]['percent']:
                    renames[most_likely] = {'fcn':k, 'percent':percent}
        return renames


