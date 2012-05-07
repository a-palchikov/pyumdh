"""Diffing processor"""

from multiprocessing import Pool, cpu_count, freeze_support
import pyumdh.config as config
from pyumdh.backtrace import Backtrace
from pyumdh.utils import SymProxy
from optparse import OptionParser
import operator
import re
import os
import sys
import pdb


def _binary_backtrace_path(filepath):
    binfn = os.path.basename(filepath)
    binfn = '%s.bin' % binfn[:-4]
    return os.path.abspath(os.path.join(os.path.dirname(filepath), binfn))

def _generate_binary_backtrace(datafile):
    binpath = _binary_backtrace_path(datafile)
    if not os.path.exists(binpath):
        trace = Backtrace(datafile)
        trace.save(binpath)

def _load_binary_backtrace(datafile):
    trace = Backtrace()
    trace.load(_binary_backtrace_path(datafile))
    return trace

def _is_backtrace_binary(datafile):
    try:
        if isinstance(datafile, basestring):
            close = True
            datafile = io.open(datafile, 'rb')
        if datafile.read(len(Backtrace.magic)) != magic:
            return False
        return True
    finally:
        if close:
            datafile.close()

def _load_backtraces(tracefiles):
    """Helper to load trace logs from original or binary store.
    It assumes that (trace) binary representation files end with `.bin'
    """
    """
    p = Pool(len(tracefiles) if len(tracefiles) < cpu_count() else None)
    p.map(_generate_binary_backtrace, tracefiles)
    p.close()
    p.join()
    """
    return map(_load_binary_backtrace, tracefiles)

# FIXME tbd
_USAGE = """
"""

if __name__ == '__main__':
    freeze_support()
    parser = OptionParser()
    parser.add_option('--data-file', dest='logs', action='append', \
            default=[], \
            help='specify memory logs to diff; at (least and most) two are required')
    parser.add_option('--out-file', dest='outfile', \
            help='specify file to save results to (defaults to stdout)' \
            ' (names the binary file if --save-binary has been specified!)')
    parser.add_option('--duplicates', action='store_true', \
            help='do not remove duplicates')
    parser.add_option('--trusted-pattern', dest='patterns', \
            action='append', default=[], \
            help='specify additional trusted pattern')
    parser.add_option('--save-binary', dest='savebin', default=False, \
            action='store_true', help='specify that results be saved ' \
            'in binary form (defaults to %default)')
    parser.add_option('--sym-cache', dest='symcache', default=None, \
            help='specify file to use for symbol caching; this will ' \
            'significantly speed symbol lookups')

    if not sys.argv[1:]:
        parser.print_help()
        sys.exit(1)

    (opts, args) = parser.parse_args()
    sys.argv[:] = args

    from symprovider import symbols
    from filters import filter_on_foreign_module, grep_filter
    traces = _load_backtraces(opts.logs or args)
    with symbols(bin_path=';'.join(config.DBG_BIN_PATHS), \
                    sym_path=';'.join(config.DBG_SYMBOL_PATHS)) as _sym:
        sym = SymProxy(_sym, opts.symcache)
        patterns = config.TRUSTED_PATTERNS if 'TRUSTED_PATTERNS' in \
                            dir(config) else []
        for p in opts.patterns:
            patterns.append(re.compile(p), re.IGNORECASE)
        modules = config.TRUSTED_MODULES if 'TRUSTED_MODULES' in \
                            dir(config) else []
        grepfn = filter_on_foreign_module( \
                    traces[-1], symbols=sym, \
                    trustedmodules=modules, \
                    trustedpatterns=patterns)
        # compute diff for the last two data files
        diff = traces[-2].diff_with(traces[-1], grepfn=grepfn)
        if not opts.duplicates and config.REMOVE_DUPLICATES:
            diff.compress_duplicates()
        if not opts.savebin:
            if opts.outfile:
                fileobject = open(opts.outfile, 'w')
            else:
                fileobject = sys.stdout
            diff.dump_allocs(symbols=sym, fileobject=fileobject)
            if opts.outfile:
                fileobject.close()
        else:
            diff.save(opts.outfile)
        if opts.symcache and not os.path.exists(opts.symcache):
            sym.save()
        #sym.dump_stats()

