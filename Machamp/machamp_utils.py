import r2pipe

class MachampUtils:
    def __init__(self, flags=[], filename=None):
        if not filename:
            self.r2 = r2pipe.open(flags=flags)
        else:
            self.r2 = r2pipe.open(filename, flags=flags)

    def get_function_info(self):
        functions = self.r2.cmdj('aflj')
        return functions

    def get_function_info_at_addr(self, addr):
        dat = self.r2.cmdj('afij @ {}'.format(addr))
        return dat

    def get_basic_block_info(self, function):
        try:
            basic_blocks = self.r2.cmdj('afbj @ {}'.format(function))
            return basic_blocks
        except:
            return None

    def get_function_instructions(self, fname):
        ins = self.r2.cmdj('pdfj @ {}'.format(fname))
        return ins

    def find_functions_that_overlap(self, functions, maxbound, exclude=[]):
        same_functions = []
        for f in functions:
            if (f['maxbound'] == maxbound):
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

    def get_filename(self):
        return self.r2.cmd('o.').strip()

    def rename_function(self, old, new):
        self.r2.cmd('afn {} @@ {}'.format(new, old))

    def analyze_binary(self, level='aaa'):
        self.r2.cmd(level)
