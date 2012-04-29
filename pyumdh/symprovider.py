
from ctypes import *
from ctypes.wintypes import HANDLE, DWORD
import os.path
from os.path import join, exists, isfile, basename
import sys
from contextlib import contextmanager
from dynlib import wdll
import random
import pdb

DWORD64 = c_ulonglong

SymInitialize = wdll.dbghelp.SymInitializeW
SymLoadModuleEx = wdll.dbghelp.SymLoadModuleExW
SymLoadModuleEx.restype = DWORD64
SymLoadModuleEx.argtypes = [HANDLE, HANDLE, c_wchar_p, DWORD, DWORD64, DWORD, \
                            DWORD, DWORD]
SymFromAddr = wdll.dbghelp.SymFromAddrW
SymCleanup = wdll.dbghelp.SymCleanup

@contextmanager
def symbols(bin_path = None, sym_path = None):
    _id = random.randint(1, 0xffff)
    SymInitialize(_id, u';'.join((bin_path or '', sym_path or '')), False)
    provider = SymbolProvider(_id, bin_path, sym_path)
    yield provider
    provider.cleanup()

class _SYMBOL_INFO(Structure):
    _fields_ = [
      ('SizeOfStruct', c_ulong),
      ('TypeIndex', c_ulong),
      ('Reserved', c_ulonglong * 2),
      ('Index', c_ulong),
      ('Size', c_ulong),
      ('ModBase', c_ulonglong),
      ('Flags', c_ulong),
      ('Value', c_ulonglong),
      ('Address', c_ulonglong),
      ('Register', c_ulong),
      ('Scope', c_ulong),
      ('Tag', c_ulong),
      ('NameLen', c_ulong),
      ('MaxNameLen', c_ulong),
      ('Name', c_wchar * 1)
    ]

def guid_str(guid, age):
    return '{:X}{:X}{:X}{}{}'.format( \
                    guid.Data1, \
                    guid.Data2, \
                    guid.Data3, \
                    guid.Data4.encode('hex').upper(), \
                    age)

def format_symbol_module(module):
    name = basename(module).lower()
    if name.endswith('.dll') or name.endswith('.exe'):
        name = name[:-4]
    return name

class SymbolProvider(object):
    def __init__(self, id, bin_path = None, sym_path = None):
        """
        :param   bin_path   path to the binaries (optional), if None provided, 
                            default binary search algorithm is used
        :param   sym_path   path to the symbol files; if None is provided, symbols are 
                            looked up based on paths embedded in the executable
        These two parameters might later be superceded by the binary/symbol server interface
        that would allow these files to be anywhere, not only on the FS
        """
        self._id = id
        self._sym_path = sym_path
        # loaded modules as tuples (addr, module)
        self._modules = {}
        self._shutdown = False

    def cleanup(self):
        print 'SymProvider: cleanup'
        self._shutdown = True
        SymCleanup(self._id)

    def _lookup_pdb(self, module):
        """Performs simple pdb lookup - does not match pdb to the given
        module"""
        pdb_file = basename(module.CvData.Filename)
        guid = guid_str(module.CvData.GUID, module.CvData.Age)
        paths = self._sym_path.split(';')
        for p in paths:
            pdb_path = join(p, pdb_file)
            if isfile(pdb_path):
                return pdb_path
            p = join(join(p, pdb_file), guid)
            pdb_path = join(p, pdb_file)
            if isfile(pdb_path):
                return pdb_path

    def _preload_module(self, module):
        try:
            # look up corresponding pdb on the sym path
            if hasattr(module, 'CvData'):
                path = self._lookup_pdb(module)
            else:
                path = module.ModuleName
            """
            if not pdb_path:
                import requests
                requests.get('http://msdl.microsoft.com/download/symbols/%s/%s'.format(
                    module.CvData.Filename, guid_str(module.CvData.GUID,
                        module.CvData.Age))
            """
            if path:
                self._modules.update( \
                        {module.ModuleName: \
                            (SymLoadModuleEx( \
                                    self._id, 0, unicode(path), 0, \
                                    module.BaseOfImage, module.SizeOfImage, \
                                    0, 0), module) \
                        })
        except WindowsError:
            #print 'Failed to load module %s' % module.ModuleName
            pass

    def sym_from_addr(self, moduleregistry, addr):
        """
        retrieves the symbol info at given addr
        :param  addr    addr to retrieve symbol from (does not have to fall on
                        a symbol's boundary)
        returns (symbol_name, disposition, module_name, symbol_repr)
        """
        assert not self._shutdown, 'symbol provder already shut down'
        # probe the address for the ranges we already know, if None found, load the module
        # and its symbol table
        module = moduleregistry.map_to_module(addr)
        module_name = module.ModuleName if module else '<no module>'
        if module and not self._modules.get(module_name):
            self._preload_module(module)
        disp = c_ulonglong()
        addr = c_ulonglong(addr)
        sym_buf = create_unicode_buffer(128)
        sym_ptr = POINTER(_SYMBOL_INFO)
        sym = cast(sym_buf, sym_ptr)
        sym.contents.SizeOfStruct = sizeof(_SYMBOL_INFO)
        sym.contents.MaxNameLen = (258 - sym.contents.SizeOfStruct) / 2
        # do not use automatic error check for this api
        del SymFromAddr.errcheck
        if not SymFromAddr(self._id, addr, byref(disp), sym):
            return (None, c_ulonglong(addr.value-module.BaseOfImage) if module else\
                    c_ulonglong(), module_name)
        return (sym_buf[42:42+sym.contents.NameLen], disp, module_name)

if __name__ == '__main__':
    trace = Backtrace(sys.argv[1])
    with symbols(trace,
            sym_path=u'd:\\blah-blah\\lib;' \
                    'd:\\vpdev\\websymbols') as sym:
        print sym.sym_from_addr(0x75656238)
