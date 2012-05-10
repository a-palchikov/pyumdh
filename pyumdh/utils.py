# vim:ts=4:sw=4:expandtab

"""Collection of utils"""

import os
import sys
import pdb
#import types
try:
    import cpickle as pickle
except ImportError:
    import pickle

__all__ = ['file_open', 'SymProxy', 'module_to_dict', 'module_path', \
            'data_dir', 'Dictify']

def _frozen():
    return hasattr(sys, 'frozen')

def module_path():
    """Returns path to this executable/script."""
    if _frozen():
        return os.path.dirname(unicode(sys.executable, \
            sys.getfilesystemencoding()))
    return os.path.dirname(unicode(__file__, sys.getfilesystemencoding()))

def module_to_dict(module):
    return {k:v for k,v in vars(module).iteritems() if k[2:] != '__' and \
                                                        k[-2:] != '__'}

def data_dir(workdir):
    """Retrieve the directory where data files are stored.
    Creates directory if non-existent.
    """
    datapath = workdir
    if not datapath:
        datapath = module_path()
    else:
        datapath = os.path.abspath(datapath)
    if not os.path.exists(datapath):
        os.mkdir(datapath)
    return datapath


def file_open(fileobject, mode):
    close = False
    if isinstance(fileobject, basestring):
        # tried with io - it has locked my system up when I had a bug and tried
        # to access file beyond valid range
        fileobject = open(fileobject, mode)
        close = True
    return (fileobject, close)

# thanks to stackoverflow.com for the idea
def fmt_size(size):
    for klass in ['bytes', 'K', 'Mb', 'Gb']:
        if size < 1024.0:
            _floor = int(size)
            return ('%3.2f %s' if _floor<size else '%d %s') % (size, klass)
        size /= 1024.0
    _floor = int(size)
    return ('%3.2f %s' if _floor<size else '%d %s') % (size, 'Tb')


class Dictify(object):
    def __init__(self, module):
        #assert(isinstance(module, types.ModuleType))
        self._module = {k:v for k,v in vars(module).iteritems() \
                        if k[2:] != '__' and k[-2:] != '__'}

    def __getattr__(self, name):
        return self._module[name]

    __getitem__ = __getattr__

    def get(self, name, default=None):
        return self._module.get(name, default)

    def update(self, _dict):
        if isinstance(_dict, Dictify):
            self._module.update(_dict._module)
        else:
            self._module.update(dict(_dict))

    def setdefault(self, name, default):
        return self._module.setdefault(name, default)

    def iteritems(self):
        return self._module.iteritems()

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
        fileobject, close = file_open(fileobject or self._cachefile, 'wb')
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


