import re
import pdb
from collections import namedtuple
#from itertools import ifilter
from pyumdh.symprovider import format_symbol_module
import os
import sys
import pyumdh.config as config
try:
    import cPickle as pickle
except ImportError:
    import pickle


# parsing helpers
def _next_line(f):
    """Skip empty lines and comments"""
    line = f.readline()
    while line:
        if line == '\n' or line.startswith('//'):
            # skip empty lines and comments
            line = f.readline()
            continue
        break
    return line

def _parse_stack(f):
    """Parse stack as a list of addresses"""
    addrs = []
    pos = f.tell()
    line = f.readline()
    # FIXME check for stack condition first (that it starts with '\t') and
    # rewind/bail out otherwise
    if not line or line == '\n':
        return addrs
    elif not line.startswith('\t'):
        f.seek(pos, os.SEEK_SET)
        return addrs
    while line and line != '\n' and line.startswith('\t'):
        addrs.append(int(line.strip('\t\n'), 16))
        line = f.readline()
    return addrs


class Backtrace(object):
    """Process memory snapshot.

    Heaps: dict of allocations, keyed by heap handle
        {heaphandle: allocations}
    Allocations: dict of allocation samples keyed by trace id
        {traceid: allocation(id, stack, allocs=[(requested, overhead, address)])}
    """

    _heaphandle_re_ = re.compile(r'Heap ([0-9A-Fa-f]+) Hogs')
    _allocstats_re_ = re.compile(r'([0-9A-Fa-f]+) bytes \+ ([0-9A-Fa-f]+) at ' \
            '([0-9A-Fa-f]+) by BackTrace([0-9A-Fa-f]+)')
    _module_re_ = re.compile(r'([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+) ([^\n]+)$')
    sample = namedtuple('sample', 'requested overhead address')
    allocation = namedtuple('allocation', 'stack allocs')
    module = namedtuple('module', 'BaseOfImage SizeOfImage ModuleName')

    def __init__(self, datafile=None):
        """Constructs a Backtrace by parsing the specified file"""
        # heaps is a dict of dicts each representing an individual allocation
        self._heaps = {}
        self._modules = {}
        if datafile:
            if isinstance(datafile, basestring):
                with open(datafile, 'r') as f:
                    self._parse(f)
            else:
                self._parse(datafile)

    # module registry protocol
    def map_to_module(self, addr):
        for module in self._modules.itervalues():
            if module.BaseOfImage <= addr < module.BaseOfImage + \
                                            module.SizeOfImage:
                return module

    def dump_stats(self, fileobject=None):
        def alloc_key(alloc):
            return len(alloc[1])
        """Dump backtrace stats"""
        heaps = sorted(self._heaps.iteritems(), key=alloc_key, reverse=True)
        for k,v in heaps:
            self._print('Heap: 0x%X, allocations: %d' % (k, len(v)), fileobject)

    def dump_modules(self, fileobject=None):
        self._print('Modules:', fileobject)
        for module in self._modules.itervalues():
            self._print('%s @ 0x%X, size=%d' % (module.ModuleName, module.BaseOfImage, \
                    module.SizeOfImage), fileobject)

    def dump_allocs(self, handle=None, symbols=None, grepfn=None, \
            fileobject=None):
        """Dumps allocations (for specified heap or all).

        |grepfn|        filter to run on allocations
                        must comply to the filter protocol
        """
        if handle:
            try:
                heaps = ((handle, (self._heaps[handle])),)
            except KeyError:
                raise RuntimeError('Invalid heap handle provided: 0x%X' % \
                        int(handle))
        else:
            heaps = self._heaps.iteritems()
        if not grepfn:
            grepfn = bool
        self._print('Allocations:', fileobject=fileobject)
        for handle, heap in heaps:
            self._print('Heap @ 0x%X' % handle, fileobject=fileobject)
            for traceid, alloc in filter(grepfn, heap.iteritems()):
                self._print('Traceid: 0x%x' % int(traceid, 16), fileobject=fileobject)
                self._print('Allocations: [%s]' % ','.join(map(hex, \
                    [addr for _,_,addr in alloc.allocs])), fileobject)
                self._dump_stack(alloc.stack, symbols=symbols, \
                        fileobject=fileobject)


    def diff_with(self, backtrace, grepfn=None):
        """Compute a diff to backtrace and return a new instance of
        Backtrace.

        |grepfn|     filter to run on allocations
                     must comply to the filter protocol
        """
        def diff_filter(traces):
            def _filter(item):
                return item[0] in traces
            return _filter
        if not grepfn:
            grepfn = bool
        diff = Backtrace()
        diff._modules = backtrace._modules
        for handle, heap in self._heaps.iteritems():
            # work for each overlapping heap
            otherheap = backtrace._heaps.get(handle)
            if otherheap:
                otherheapset = frozenset(otherheap)
                # filter all traces not present in original heap
                difftraces = otherheapset.difference(heap)
                # FIXME maybe treat dicts and iterables alike as values for
                # self._heaps???
                diffallocs = filter(grepfn, filter(diff_filter(difftraces), \
                                    otherheap.iteritems()))
                diffheap = diff._heaps.setdefault(handle, dict(diffallocs))
                # now, compute the differences on the allocation level
                commontraces = otherheapset.intersection(heap)
                for trace in commontraces:
                    alloc = otherheap.get(trace)
                    a0 = frozenset(heap.get(trace).allocs)
                    a1 = frozenset(otherheap.get(trace).allocs)
                    adiff = list(a1 - a0)
                    # skip over this trace if the grep is negative
                    if adiff and grepfn((None, alloc)):
                        allocdiff = self.allocation(stack=alloc.stack, \
                                allocs=adiff)
                        diffheap.setdefault(trace, allocdiff)
        return diff

    def save(self, fileobject):
        # FIXME im broken
        # persist in redis?
        close = False
        if isinstance(fileobject, basestring):
            close = True
            fileobject = open(fileobject, 'wb')
        pickle.dump(self, fileobject)
        if close:
            fileobject.close()

    def _parse(self, f):
        """Parse the data"""
        line = self._parse_modules(f)
        while line:
            if line.startswith('*- - - - - - - - - - Heap'):
                heaphandle = \
                        int(self._heaphandle_re_.search(line).group(1), 16)
                self._heaps.update({heaphandle: self._parse_heap(f)})
            line = _next_line(f)

    def _parse_heap(self, f):
        allocs = {}
        line = _next_line(f)
        while line:
            m = self._allocstats_re_.search(line)
            if m:
                requested, overhead, addr, traceid = m.group(1, 2, 3, 4)
                item = allocs.setdefault(traceid, None)
                # parse allocation
                stack = _parse_stack(f)
                sample = self.sample(requested=int(requested, 16), \
                                    overhead=int(overhead, 16), \
                                    address=int(addr, 16))
                if item:
                    # add this allocation stats to the already existent trace
                    # sample
                    item.allocs.append(sample)
                else:
                    allocs.update({traceid: self.allocation(stack=stack, \
                                                allocs=[sample])})
            elif line.startswith('*- - - - - - - - - - End of data for heap'):
                break
            line = _next_line(f)
        return allocs

    def _parse_modules(self, f):
        line = f.readline()
        # rewind to module list
        while line and 'Base Size Module' not in line:
            line = f.readline()
        # set ptr on the first module
        line = f.readline()
        while line and not line.startswith('*-'):
            m = self._module_re_.search(line)
            if m:
                address, size, path = m.group(1, 2, 3)
                self._modules.update( \
                    {os.path.basename(path): \
                            self.module(BaseOfImage=int(address, 16), \
                                        SizeOfImage=int(size, 16), \
                                        ModuleName=path) \
                    })
            line = f.readline()
        return line

    def _dump_stack(self, stack, symbols=None, fileobject=None):
        """Dump stack for the specified allocation."""
        for addr in stack:
            symbol, disp, module_name = symbols.sym_from_addr(self, addr)
            if not symbol:
                symbol = os.path.basename(module_name)
            disp = hex(disp.value)
            module_name = format_symbol_module(module_name)
            self._print('\t%(module_name)s!%(symbol)s+%(disp)s' % (locals()), \
                    fileobject)

    def _print(self, message, fileobject=None):
        if not fileobject:
            fileobject = sys.stdout
        fileobject.write(message + '\n')


if __name__ == '__main__':
    import sys
    # Use: backtrace[.py] datafile1 datafile2 ... datafilen
    if len(sys.argv) < 3:
        print 'backtrace[.py] datafile1 datafile2 .. datafilen'
        print '\tat least two data files are required for analysis'
        sys.exit(1)
    from symprovider import symbols
    from filters import filter_on_foreign_module, grep_filter
    traces = map(Backtrace, sys.argv[1:])
    with symbols(bin_path=';'.join(config.DBG_BIN_PATHS), \
                    sym_path=';'.join(config.DBG_SYMBOL_PATHS)) as sym:
        patterns = config.TRUSTED_PATTERNS if 'TRUSTED_PATTERNS' in \
                            dir(config) else []
        modules = config.TRUSTED_MODULES if 'TRUSTED_MODULES' in \
                            dir(config) else []
        grepfn = filter_on_foreign_module(traces[-1], symbols=sym, \
            trustedmodules=modules, trustedpatterns=patterns)
        # compute diff for the last two data files
        diff = traces[-2].diff_with(traces[-1], grepfn=grepfn)
        pdb.set_trace()
        diff.dump_allocs(symbols=sym, handle=0x5B90000)
