import r2pipe
import hashlib
import codecs
import argparse
import yaml

class Machamp:
    def __init__(self, filename=None):
        if not filename:
            self.r2 = r2pipe.open()
        else:
            self.r2 = r2pipe.open(filename)

    def get_function_info(self):
        functions = self.r2.cmdj('aflj')
        return functions

    def get_basic_block_info(self, function):
        basic_blocks = self.r2.cmdj('afbj @ {}'.format(function))
        return basic_blocks

    def get_basic_block_id(self, addr, bb):
        if bb == None:
            return -1
        for i in range(len(bb)):
            block = bb[i]
            if block['addr'] == addr:
                return i
        return -1

    def get_basic_block_call(self, addr):
        disas = self.r2.cmdj('pdbj @ {}'.format(addr))
        num_call = 0
        if disas == None:
            return 0
        for d in disas:
            if d['type'] == 'call':
                #print(hex(d['offset']))
                #print(d['disasm'])
                num_call += 1
        return num_call

    def form_machamp_block_string(self, index, bb):
        block = bb[index]
        fail = (-1 if 'fail' not in block.keys()
                else self.get_basic_block_id(block['fail'], bb))
        jump = (-1 if 'jump' not in block.keys()
                else self.get_basic_block_id(block['jump'], bb))
        call = self.get_basic_block_call(block['addr'])
        string = '{}:j{};f{};c{}'.format(index, jump, fail, call)
        #print(string)
        return bytes(string, 'UTF-8')

    def form_machamp_hash(self, function):
        basic_blocks = self.get_basic_block_info(function)
        machamp_hash = ''
        for i in range(len(basic_blocks)):
            m_string = self.form_machamp_block_string(i, basic_blocks)
            m_hash = hashlib.md5(m_string)
            mb64 = codecs.encode(m_hash.digest(), 'base64')[:6]
            machamp_hash += mb64.decode('UTF-8')
        return machamp_hash

    def form_machamp_table(self, exclude=[], quiet=False):
        if not quiet: print('Running aaa first, this may take a while...')
        self.r2.cmd('aaa')
        if not quiet: print('Removing any overlapping functions...')
        self.remove_overlapping_functions()
        if not quiet: print('Generating Machamp table...')
        table = {}
        funcs = self.r2.cmdj('aflj')
        for f in funcs:
            if f['name'] not in exclude:
                h = self.form_machamp_hash(f['name'])
                if not h == None and not h == '':
                    table[f['name']] = h
        return table

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

    def find_functions_that_overlap(self, functions, maxbound, exclude=[]):
        same_functions = []
        for f in functions:
            if f['maxbound'] == maxbound and f['name'] not in exclude:
                same_functions.append({'name':f['name'], 'offset':f['offset']})
        return same_functions

    def sort_functions(self, overlap):
        offsets = [f['offset'] for f in overlap]
        offsets.sort()
        return offsets

    def remove_overlapping_functions(self):
        functions = self.r2.cmdj('afllj')
        check = []
        for f in functions:
            found = [{'name':f['name'], 'offset':f['offset']}]
            overlap = self.find_functions_that_overlap(functions,
                                                       f['maxbound'],
                                                       [f['name']])
            found += overlap
            if len(found) < 2:
                continue
            ordered_found = self.sort_functions(found)
            for i in range(len(ordered_found)-1):
                self.r2.cmd('afu {} @@={}'.format(ordered_found[i+1],
                                                  ordered_found[i]))


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
            print('{} is most likely {}'.format(orig, f))
            self.r2.cmd('afn {} @@ {}'.format(f, orig))

    def get_function_renames(self, t1, t2, exclude=[], threshold=80):
        renames = {}
        for k in t1:
            if k not in exclude:
                most_likely, percent = self.get_most_likely_function(t1[k], t2)
                if not most_likely in renames.keys() and percent >= threshold:
                    renames[most_likely] = {'fcn':k, 'percent':percent}
                elif percent >= threshold and percent > renames[most_likely]['percent']:
                    renames[most_likely] = {'fcn':k, 'percent':percent}
        return renames

    def get_filename(self):
        return self.r2.cmd('o.').strip()


