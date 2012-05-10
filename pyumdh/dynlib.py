from ctypes import windll, WinDLL, LibraryLoader, GetLastError, \
        windll as windll0, FormatError, WinError, Structure
from ctypes.wintypes import WORD, BYTE
import pyumdh.utils as utils
import os
import sys
import pdb

__all__ = ['wdll', 'windll']

def _win64():
    import platform
    arch = platform.machine().lower()
    win64 = arch == 'amd64' or arch == 'ia64'
    global _win64
    def _win64(): return win64
    return _win64()


NULL = 0

DONT_RESOLVE_DLL_REFERENCES         = 0x00000001
LOAD_WITH_ALTERED_SEARCH_PATH       = 0x00000008
LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR    = 0x00000100
LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200
LOAD_LIBRARY_SEARCH_DEFAULT_DIRS    = 0x00001000

# *FIXME* differentiate 32/64bit versions of dbghelp.dll
# (or use alternate _EXCEPTION_RECORD for 64 bits)
class WindowsLibrary(WinDLL):
    """Locates and loads a library using alternate search strategy
    """
    def __init__(self, name, path, *args, **kwargs):
        from os.path import abspath, join, split
        # LoadLibrary will append the .dll suffix if missing
        for p in path:
            dll_path = join(p, name)
            if dll_path[-4:] != '.dll':
                dll_path += '.dll'
            handle = windll.kernel32.LoadLibraryExW(unicode(dll_path), NULL, \
                    #LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR)
                    LOAD_WITH_ALTERED_SEARCH_PATH)
            if handle:
                break
        else:
            handle = windll.kernel32.LoadLibraryW(unicode(dll_path))
            if not handle:
                handle = windll.kernel32.LoadLibraryW(unicode(name))

        super(WindowsLibrary, self).__init__(*args, name=name, handle=handle, **kwargs)

class WindowsLibraryLoader(LibraryLoader):
    def __init__(self, *args, **kwargs):
        self._path = []
        super(WindowsLibraryLoader, self).__init__(*args, **kwargs)
    def add_path(self, fpath):
        self._path.append(fpath)
    def __getattr__(self, name):
        if name[0] == '_':
            raise AttributeError(name)
        dll = self._dlltype(name, self._path)
        setattr(self, name, dll)
        return dll

wdll = WindowsLibraryLoader(WindowsLibrary)
wdll.add_path(os.path.join(utils.module_path(), 'x64' if _win64() else 'x86'))


from logging import getLogger

class WinDll(WinDLL):
    """
    Implements a windows library type that wraps all calls to provide error logging
    and throws WinError if a wrapped function call fails.
    Default error checking assumes that the wrapped api call returns zero in case of
    errors.
    This behaviour can be overriden by providing a callable to check for error
    condition:
        api_fn.errfn = lambda ret, args: check(ret)
    This also provides the ability to bypass error checking by providing a
    function to check errors that always defaults to True
    """
    def __init__(self, *args, **kwargs):
        super(WinDll, self).__init__(*args, **kwargs)

    def _error_check(self, ret, func, args):
        lasterror = GetLastError()
        errfn = getattr(func, 'errfn', None)
        if errfn:
            # custom error return check function defined
            failed = errfn(ret, args)
        else:
            failed = not ret
        if failed:
            #print '%s failed, lasterror=%x' % (func.__name__, lasterror)
            """
            self._log.critical('call to {0} failed with error {1} ({2})' \
                                '(hr=0x{3:08x})'.format(func.__name__, \
                            lasterror, FormatError(lasterror), \
                            lasterror&0xffffffff))
            """
            raise WinError(lasterror)
        return ret

    def __getitem__(self, name_or_ordinal):
        func = super(WinDll, self).__getitem__(name_or_ordinal)
        func.errcheck = self._error_check
        return func

windll = LibraryLoader(WinDll)
