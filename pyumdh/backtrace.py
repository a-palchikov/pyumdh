# vim:ts=4:sw=4:expandtab
"""Implements Backtrace - class for reading and processing memory snapshots"""

import re
import operator
import difflib
import math
import os
import sys
import struct
import io
from collections import namedtuple
from itertools import combinations, groupby, ifilter, chain, izip, takewhile
from pyumdh.symprovider import format_symbol_module
import pyumdh.config as config
from pyumdh.symprovider import symbols
import pyumdh.utils as utils
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
import pdb


def _quick_compare_stacks(stack1, stack2, threshold=0.7):
    """Compare stacks given a tolerance level."""
    stacklen = max(len(stack1), len(stack2))
    matchlen = len([a for a in takewhile(lambda x: x[0] == x[1], izip(stack1, \
                        stack2))])
    return matchlen >= int(stacklen * threshold)

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
    """Parse stack as a list of addresses.
    Handles aliases stacks by combining them into a separate list.
    Returns (stack, aliases) tuple.
    """
    (addrs, originalstack) = ([], [])
    aliases = []
    pos = f.tell()
    line = f.readline()
    # FIXME add support for aliased stacks
    # not sure which would be better:
    #   > creating fake traces for aliased stacks and listing these traces as
    #       aliases in the original trace
    #   > keeping them around in the original trace
    if not line or line == '\n':
        return (addrs, [])
    elif not line.startswith('\t'):
        f.seek(pos, os.SEEK_SET)
        return (addrs, [])
    while line and line != '\n' and line.startswith('\t'):
        addr = line.strip('\t\n')
        if addr == 'Alias': # alias stack follows
            if not originalstack:
                originalstack = addrs
            addrs = []
            aliases.append(addrs)
        else:
            addrs.append(int(addr, 16))
        line = f.readline()
    return (originalstack or addrs, aliases)


class Backtrace(object):
    """Process memory snapshot.

    Heaps: dict of allocations, keyed by heap handle
        {heaphandle: allocations}
    Allocations: dict of allocation samples keyed by trace id
        {traceid: allocation(id, stack, allocs=[(requested, overhead,
                                                    address)])}
    """

    _heaphandle_re_ = re.compile(r'Heap ([0-9A-Fa-f]+) Hogs')
    _allocstats_re_ = re.compile(r'([0-9A-Fa-f]+) bytes \+ ([0-9A-Fa-f]+) at ' \
            '([0-9A-Fa-f]+) by BackTrace([0-9A-Fa-f]+)')
    _module_re_ = re.compile(r'([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+) ([^\n]+)$')
    sample = namedtuple('sample', 'requested overhead address')
    allocation = namedtuple('allocation', 'stack aliases allocs')
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
        self._uniqueallocs = {}
        if datafile:
            if isinstance(datafile, basestring):
                self._path = datafile
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
        def sumaddrs(iterable):
            _sum = 0
            for requested, overhead, _ in iterable:
                _sum += requested + overhead
            return _sum

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
                iterable = ifilter(lambda i: i[0] in self._uniqueallocs, \
                                    heap.iteritems())
            else:
                iterable = heap.iteritems()
            for traceid, alloc in ifilter(grepfn, iterable):
                mergeallocs = self._uniqueallocs.get(traceid) or []
                self._print('Traceid: 0x%x' % traceid, fileobject=fileobject)
                self._print('Memory entries: %d' % \
                        (len(alloc.allocs)+len(mergeallocs)), fileobject)
                self._print('Memory size: %s' % utils.fmt_size( \
                        sumaddrs(chain(alloc.allocs, \
                        mergeallocs))), fileobject)
                self._print('Memory: [%s]' % ','.join(map(hex, \
                    [addr for _,_,addr in chain(alloc.allocs, \
                                                mergeallocs)])), \
                            fileobject)
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
                                                    aliases=[],
                                                    allocs=adiff)
                        diffheap.setdefault(trace, diffalloc)
                        diff._allocs.update({trace: diffalloc})
        return diff

    def compress_duplicates(self, level):
        assert(level is not None)
        duplicates = []
        def aggressively(heap):
            for pair in combinations(heap.iterkeys(), 2):
                seq1 = heap[pair[0]]
                seq2 = heap[pair[1]]
                foo = difflib.SequenceMatcher(None, seq1.stack, \
                                        seq2.stack, autojunk=False)
                if foo.quick_ratio() > 0.88:
                    yield pair

        def strictly(heap):
            for pair in combinations(heap.iterkeys(), 2):
                if _quick_compare_stacks(seq1.stack, seq2.stack):
                    yield pair

        compressor = aggressively if level == \
                        utils.duplicate_levels.aggressive else strictly
        # FIXME maybe return a copy of Backtrace with duplicates removed
        for heap in self._heaps.itervalues():
            if len(heap) > 0:
                duplicates = [_ for _ in compressor(heap)]
            if duplicates:
                seen = set() # traces we've seen so far
                mergeallocs = {}
                for key, group in groupby(duplicates, \
                                            key=operator.itemgetter(0)):
                    #if key not in seen:
                    #    self._uniqueallocs.update({key: self._allocs.get(key)})

                    # update seen set with items that need not be repeated in
                    # uniqueallocs
                    tracelist = map(operator.itemgetter(1), group)
                    seen.update(tracelist)
                    if key not in seen:
                        # associate each trace that makes it into uniqueallocs
                        # with the list of its duplicate so that we can merge
                        # allocations later
                        mergeallocs[key] = tracelist
                # now, accommodate all allocations that weren't flagged as duplicates
                # into self._uniqueallocs paired with allocations from duplicates
                uniqueallocs = set(set(self._allocs.keys()) - seen)
                for traceid in uniqueallocs:
                    allocs = []
                    mergegroup = mergeallocs.get(traceid)
                    if mergegroup:
                        for tid in mergegroup:
                            allocs.extend(self._allocs[tid].allocs)
                    self._uniqueallocs[traceid] = allocs
                #self._uniqueallocs.update({key: self._allocs[key] for key in \
                #    self._allocs.iterkeys() if key not in seen})

    def save(self, fileobject):
        """Saves a Backtrace to fileobject in binary form"""
        try:
            fileobject, close = utils.file_open(fileobject, 'wb')

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
                if self._uniqueallocs:
                    iterable = ifilter(lambda i: i[0] in self._uniqueallocs, \
                                        heap.iteritems())
                    numallocs = len(self._uniqueallocs)
                else:
                    iterable = heap.iteritems()
                    numallocs = len(heap)
                fileobject.write(struct.pack('LL', handle, numallocs))
                for traceid, allocation in iterable:
                    mergeallocs = self._uniqueallocs.get(traceid) or []
                    numaddrs = len(allocation.allocs) + len(mergeallocs)
                    fileobject.write(struct.pack('LLL', traceid, \
                            len(allocation.stack), \
                            numaddrs))
                    # allocation
                    for addr in allocation.stack:
                        fileobject.write(struct.pack('L', addr))
                    for m, sample in enumerate(chain(allocation.allocs, \
                                                    mergeallocs)):
                        fileobject.write(struct.pack('LLL', sample.requested, \
                            sample.overhead, sample.address))
                    #else:
                    #    assert(m+1 == numallocs)
        finally:
            if close:
                fileobject.close()

    def load(self, fileobject):
        """Loads a Backtrace from a binary representation.
        See self.save() for the persisting counterpart.
        """
        try:
            fileobject, close = utils.file_open(fileobject, 'rb')

            data = fileobject
            #data = StringIO(fileobject.read())
            if data.read(len(self.magic)) != self.magic:
                raise ValueError('not binary trace file')
            dword = struct.calcsize('L')
            # modules
            nummodules = struct.unpack_from('L', data.read(dword))[0]
            for i in xrange(nummodules):
                base, size, modulenamelen = struct.unpack_from('LLL', \
                        data.read(dword*3))
                strfmt = '%ds' % modulenamelen
                strlen = struct.calcsize(strfmt)
                modulename = struct.unpack_from(strfmt, data.read(strlen))[0]
                self._modules.setdefault(os.path.basename(modulename), \
                                        self.module(base, size, modulename))
            # heaps
            numheaps = struct.unpack_from('L', data.read(dword))[0]
            for i in xrange(numheaps):
                handle, numallocs = struct.unpack_from('LL', data.read(dword*2))
                heap = {}
                for j in xrange(numallocs):
                    traceid, stacklen, allocslen = struct.unpack_from('LLL', \
                            data.read(dword*3))
                    # allocation
                    stack = []
                    for k in xrange(stacklen):
                        stack.append(struct.unpack_from('L', data.read(dword))[0])
                    allocs = []
                    for k in xrange(allocslen):
                        allocs.append(self.sample(*struct.unpack_from('LLL', \
                            data.read(dword*3))))
                    allocation = self.allocation(stack=stack, aliases=[], \
                                                    allocs=allocs)
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
                stack, aliases = _parse_stack(f)
                sample = self.sample(requested=int(requested, 16), \
                                    overhead=int(overhead, 16), \
                                    address=int(addr, 16))
                if item:
                    # add this allocation stats to the already existent trace
                    # sample
                    item.allocs.append(sample)
                else:
                    allocs.update({traceid: self.allocation(stack=stack, \
                                            aliases=aliases, allocs=[sample])})
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
    if not sys.argv[1:]:
        print 'Syntax: backtrace[.py] datafile [sym-cache]'
        sys.exit(1)
    trace = Backtrace()
    trace.load(sys.argv[1])
    with symbols(bin_path=';'.join(config.DBG_BIN_PATHS), \
                    sym_path=';'.join(config.DBG_SYMBOL_PATHS)) as _sym:
        symcache = sys.argv[2:]
        sym = utils.SymProxy(_sym, symcache[0]) if symcache else _sym
        trace.dump_allocs(symbols=sym)

