"""Collection of utils"""

import os
try:
    import cpickle as pickle
except ImportError:
    import pickle

__all__ = ['file_open', 'SymProxy']

def file_open(fileobject, mode):
    close = False
    if isinstance(fileobject, basestring):
        # tried with io - it has locked my system up when I had a bug and tried
        # to access file beyond valid range
        fileobject = open(fileobject, mode)
        close = True
    return (fileobject, close)


class SymPassthrough(object):
    def __init__(self, symbols):
        self._symbols = symbols
    def sym_from_addr(self, trace, addr):
        return self._symbols.sym_from_addr(trace, addr)
    def dump_stats(self):
        pass

class SymProxy(object):
    """Basic symbol caching proxy capable of serializing itself in binary form."""
    def __init__(self, symbols, cachefile):
        self._symbols = symbols
        self._symcache = {}
        self._cachefile = cachefile
        if cachefile and os.path.exists(cachefile):
            self.load()

    def sym_from_addr(self, trace, addr):
        module = trace.map_to_module(addr)
        if module:
            rva = addr - module.BaseOfImage
            sym = self._symcache.get(rva)
            if not sym:
                sym = self._symbols.sym_from_addr(trace, addr)
                sym = self._symcache.setdefault(rva, [0, sym])
            sym[0] += 1
            return sym[1]
        else:
            return self._symbols.sym_from_addr(addr)

    def save(self, fileobject=None):
        fileobject, close = _open(fileobject or self._cachefile, 'wb')
        pickle.dump(self._symcache, fileobject)
        if close:
            fileobject.close()

    def load(self, fileobject=None):
        fileobject, close = file_open(fileobject or self._cachefile, 'rb')
        self._symcache = pickle.load(fileobject)
        if close:
            fileobject.close()

    def dump_stats(self, fileobject=None):
        import sys
        import operator
        """Dump symbol frequency stats."""
        if not fileobject:
            fileobject = sys.stdout
        symbols = sorted(self._symcache.itervalues(), key=operator.itemgetter(0), \
                reverse=True)
        for frequency, sym in symbols:
            fileobject.write('%d: %s\n' % (frequency, sym[0]))


