
import re
import operator
import difflib
import math
import os
import sys
import struct
import io
from collections import namedtuple
from itertools import combinations, groupby
from pyumdh.symprovider import format_symbol_module
import pdb


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
    magic = 'hdmuyp'

    def __init__(self, datafile=None):
        """Constructs a Backtrace by parsing the specified file"""
        # heaps is a dict of dicts each representing an individual allocation
        self._heaps = {}
        # top-level allocations dict (this is where _all_ allocations
        # irregardless of heap they belong to are stored)
        self._allocs = {}
        self._modules = {}
        # unique traces
        self._uniqueallocs = set()
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
            if self._uniqueallocs:
                iterable = filter(lambda i: i[0] in self._uniqueallocs, \
                                    heap.iteritems())
            else:
                iterable = heap.iteritems()
            for traceid, alloc in filter(grepfn, iterable):
                self._print('Traceid: 0x%x' % traceid, fileobject=fileobject)
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
                otherheapset = frozenset(otherheap.iterkeys())
                # filter all traces not present in original heap
                difftraces = otherheapset.difference(heap.iterkeys())
                # FIXME maybe treat dicts and iterables alike as values for
                # self._heaps???
                diffdct = {t: otherheap[t] for t in difftraces}
                diffallocs = dict(filter(grepfn, diffdct.iteritems()))
                if not diffallocs:
                    # do not persist an empty heap
                    continue
                diffheap = diff._heaps.setdefault(handle, diffallocs)
                diff._allocs.update(diffallocs)
                # now, compute the differences on the allocation level
                commontraces = otherheapset.intersection(heap)
                for trace in commontraces:
                    alloc = otherheap.get(trace)
                    a0 = frozenset(heap.get(trace).allocs)
                    a1 = frozenset(otherheap.get(trace).allocs)
                    adiff = list(a1 - a0)
                    # skip over this trace if the grep is negative
                    if adiff and grepfn((None, alloc)):
                        diffalloc = self.allocation(stack=alloc.stack, \
                                                    allocs=adiff)
                        diffheap.setdefault(trace, diffalloc)
                        diff._allocs.update({trace: diffalloc})
        return diff

    def compress_duplicates(self):
        # FIXME maybe return a copy of Backtrace with duplicates removed
        for heap in self._heaps.itervalues():
            # compute duplicates
            duplicates = []
            if len(heap) > 0:
                for pair in combinations(heap.iterkeys(), 2):
                    seq1 = heap[pair[0]]
                    seq2 = heap[pair[1]]
                    foo = difflib.SequenceMatcher(None, seq1.stack, \
                                            seq2.stack, autojunk=False)
                    if foo.quick_ratio() > 0.88:
                        # likely duplicates
                        # compute longest match and make sure it's as long as
                        # 70% of the stack
                        i, _, k = foo.find_longest_match(0, len(seq1.stack), \
                                                            0, len(seq2.stack))
                        if i == 0 and k >= int(math.floor(len(seq1) * 0.7)):
                            duplicates.append(pair)
            if duplicates:
                seen = set() # traces we've seen so far
                for key, group in groupby(duplicates, \
                                            key=operator.itemgetter(0)):
                    #if key not in seen:
                    #    self._uniqueallocs.update({key: self._allocs.get(key)})

                    # update seen set with items that need not be repeated in
                    # uniqueallocs
                    seen.update(map(operator.itemgetter(1), group))
                    # FIXME aggregate allocs from each trace in group
                    # to uniqueallocs
                # now, take all allocations that weren't flagged as duplicates
                # into self._uniqueallocs
                self._uniqueallocs = set(set(self._allocs.keys()) - seen)
                #self._uniqueallocs.update({key: self._allocs[key] for key in \
                #    self._allocs.iterkeys() if key not in seen})

    def save(self, fileobject):
        """Saves a Backtrace to fileobject in binary form"""
        try:
            close = False
            if isinstance(fileobject, basestring):
                close = True
                fileobject = io.open(fileobject, 'wb')

            fileobject.write(self.magic)
            # modules
            fileobject.write(struct.pack('L', len(self._modules)))
            for m in self._modules.itervalues():
                fileobject.write(struct.pack('LLL%ds' % len(m.ModuleName), \
                                    m.BaseOfImage, m.SizeOfImage, \
                                    len(m.ModuleName), m.ModuleName))
            # heaps
            fileobject.write(struct.pack('L', len(self._heaps)))
            for handle, heap in self._heaps.iteritems():
                fileobject.write(struct.pack('LL', handle, len(heap)))
                for traceid, allocation in heap.iteritems():
                    fileobject.write(struct.pack('LLL', traceid, \
                            len(allocation.stack), len(allocation.allocs)))
                    # allocation
                    for addr in allocation.stack:
                        fileobject.write(struct.pack('L', addr))
                    for sample in allocation.allocs:
                        fileobject.write(struct.pack('LLL', sample.requested, \
                            sample.overhead, sample.address))
        finally:
            if close:
                fileobject.close()

    def load(self, fileobject):
        """Loads a Backtrace from a binary representation.
        See self.save() for the persisting counterpart.
        """
        try:
            close = False
            if isinstance(fileobject, basestring):
                close = True
                fileobject = io.open(fileobject, 'rb')

            data = fileobject
            if data.read(len(self.magic)) != self.magic:
                raise ValueError('not binary trace file')
            dword = struct.calcsize('L')
            # modules
            nummodules = struct.unpack_from('L', data.read(dword))[0]
            for i in range(nummodules):
                base, size, modulenamelen = struct.unpack_from('LLL', \
                        data.read(dword*3))
                strfmt = '%ds' % modulenamelen
                strlen = struct.calcsize(strfmt)
                modulename = struct.unpack_from(strfmt, data.read(strlen))[0]
                self._modules.setdefault(os.path.basename(modulename), \
                                        self.module(base, size, modulename))
            # heaps
            numheaps = struct.unpack_from('L', data.read(dword))[0]
            for i in range(numheaps):
                handle, numallocs = struct.unpack_from('LL', data.read(dword*2))
                heap = {}
                for j in range(0, numallocs):
                    traceid, stacklen, allocslen = struct.unpack_from('LLL', \
                            data.read(dword*3))
                    # allocation
                    stack = []
                    for k in range(stacklen):
                        stack.append(struct.unpack_from('L', data.read(dword))[0])
                    allocs = []
                    for k in range(allocslen):
                        allocs.append(self.sample(*struct.unpack_from('LLL', \
                            data.read(dword*3))))
                    allocation = self.allocation(stack=stack, allocs=allocs)
                    heap.setdefault(traceid, allocation)
                    self._allocs.setdefault(traceid, allocation)
                self._heaps.setdefault(handle, heap)
        finally:
            if close:
                fileobject.close()

    def _parse(self, f):
        """Parse the data"""
        line = self._parse_modules(f)
        while line:
            if line.startswith('*- - - - - - - - - - Heap'):
                heaphandle = \
                        int(self._heaphandle_re_.search(line).group(1), 16)
                heapallocs = self._parse_heap(f)
                self._allocs.update(heapallocs)
                self._heaps.update({heaphandle: heapallocs})
            line = _next_line(f)

    def _parse_heap(self, f):
        allocs = {}
        line = _next_line(f)
        while line:
            m = self._allocstats_re_.search(line)
            if m:
                requested, overhead, addr, traceid = m.group(1, 2, 3, 4)
                traceid = int(traceid, 16)
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

