# some useful filter decorators

from functools import wraps
from symprovider import format_symbol_module
import re
import os
import pdb

def coroutine(f):
    @wraps(f)
    def start(*args, **kwargs):
        cro = f(*args, **kwargs)
        cro.next()
        return cro
    return start

def _sys_module(module):
    """Naively assume system modules to be those residing in %windir%"""
    sysdir = os.environ['windir'].lower()
    global _sys_module
    def _sys_module(module):
        # FIXME maybe check if the publisher is microsoft?..
        return module.lower().startswith(sysdir)
    return _sys_module(module)

def _format_symbol(sym, module):
    return '%s!%s' % (format_symbol_module(module), sym)

class ForeignModule(object):
    """Heuristics-based foreign module detection.

    Works by examining stack of an allocations, spotting the allocation point
    and checking if the allocation code belongs to a foreign module.
    Foreign modules are detected based on a list of system modules and a list
    of known low-level (system) allocators.
    """
    def __init__(self, trace, symbols=None, trustedmodules=None, \
                    trustedpatterns=None, allocatorpatterns=None):
        self._stockallocpatterns = [re.compile(r'msvcr(:?[t]|\d+)!_?(:?[mc]|re)alloc', \
                                    flags=re.IGNORECASE), \
                                re.compile(r'ntdll!rtl(re)?allocateheap', \
                                    flags=re.IGNORECASE), \
                                re.compile(r'kernelbase!\w+alloc', \
                                    flags=re.IGNORECASE)]
        self._allocpatterns = list(self._stockallocpatterns)
        if allocatorpatterns:
            for p in allocatorpatterns:
                if isinstance(p, basestring):
                    p = re.compile(p)
                self._allocpatterns.append(p)
        self._sysmodules = map(str.lower, trustedmodules or [])
        self._trustedpatterns = trustedpatterns or []
        self._symbols = symbols
        self._trace = trace
        self._toinclude = False

    def __call__(self, item):
        allocation = item[1]
        finder = self._find_allocator()
        for addr in allocation.stack:
            try:
                finder.send(addr)
            except StopIteration:
                break
        else:
            finder.close()
            self._toinclude = True
        return self._toinclude

    @coroutine
    def _find_allocator(self):
        """
        finder = self._find_allocator()
        for addr in allocation.stack:
            finder.send(addr)
        """
        def _trusted_module(module):
            return _sys_module(module) or os.path.basename(module).lower() in self._sysmodules
        def _pattern(symbol, patterns):
            for p in patterns:
                if p.search(symbol):
                    return True
        matched = False
        while not matched:
            sym, _, module = self._symbols.sym_from_addr(self._trace, (yield))
            symbol = _format_symbol(sym, module)
            if _pattern(symbol, self._allocpatterns):
                # State: system allocator matched
                # Since system allocators can be chained, skip over as many as
                # possible until we run out of frames or a foreign module has been
                # matched
                while not matched:
                    sym, _, module = self._symbols.sym_from_addr(self._trace, (yield))
                    symbol = _format_symbol(sym, module)
                    if not _pattern(symbol, self._allocpatterns):
                        if _trusted_module(module):
                            matched, self._toinclude = (True, False)
                        elif self._trustedpatterns:
                            # otherwise, complete stack processing looking for
                            # a trusted pattern (which need not be the one
                            # following the allocator!)
                            while not _pattern(symbol, self._trustedpatterns):
                                # State: matching a trusted pattern (if any)
                                sym, _, module = self._symbols.sym_from_addr(self._trace, (yield))
                                symbol = _format_symbol(sym, module)
                            matched, self._toinclude = (True, False)
                        else:
                            matched, self._toinclude = (True, True)


def filter_on_foreign_module(trace, symbols, trustedmodules=None, \
                                trustedpatterns=None, allocatorpatterns=None):
    """Filter only on allocation stacks with foreign module allocations.

    |trustedmodules|    list of trusted modules; is a simplification of
                        trustedpatterns, contains module name(s)
                        takes precedence over trustedpatterns if both have been
                        provided
                        in order to refine details on a specific module, remove it
                        from trustedmodules, and add a specific trustedpattern
                        involving the module
    |trustedpatterns|   list of trusted patterns
    |allocatorpatterns| list of trusted allocator patterns
    """
    return ForeignModule(trace=trace, symbols=symbols, \
            trustedmodules=trustedmodules, trustedpatterns=trustedpatterns, \
            allocatorpatterns=allocatorpatterns)

def grep_filter(trace, symbols, pattern):
    """Creates grep filter able to filter out allocation stacks that have a
    matching (calling) pattern in one of the frames.

    |pattern|       regex pattern to match (compiled or string)
    |trace|         trace to work on
    |symbols|       symbols provider
    """
    def _grepfn(item):
        allocation = item[1]
        stack = allocation.stack
        repattern = pattern
        if isinstance(pattern, basestring):
            repattern = re.compile(pattern)
        for addr in stack:
            sym, _, module = symbols.sym_from_addr(trace, addr)
            symbol = _format_symbol(sym, module)
            if repattern.search(symbol):
                return True
    return _grepfn

