# vim:ts=4:sw=4:expandtab

"""Diffing processor"""

from multiprocessing import Pool, cpu_count, freeze_support
import pyumdh.config as config
from pyumdh.backtrace import Backtrace
from pyumdh.utils import SymProxy
from pyumdh.symprovider import symbols
from pyumdh.filters import filter_on_foreign_module, grep_filter
import pyumdh.utils as utils
from optparse import OptionParser
from fnmatch import fnmatch
import imp
import logging
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
    p = Pool(len(tracefiles) if len(tracefiles) < cpu_count() else None)
    p.map(_generate_binary_backtrace, tracefiles)
    p.close()
    p.join()
    return map(_load_binary_backtrace, tracefiles)

# FIXME tbd
_USAGE = """
Syntax: differ[.py] [options] [datafile1] [datafile2]

--data-file options are optional, data files can be specified w/o
qualification. More over, you can specify data files by their indices:
    differ 0 1 --out-file data\\0_1.log

Will match data\\[pid]_snapshot_0.log and data\\[pid]_snapshot_1.log in the
`data' working directory if pid can be read from the cached configuration
(data\.cache.py).
"""

if __name__ == '__main__':
    freeze_support()

    binpath = utils.module_path()
    # load configuration and map its contents to a dict so that we could later
    # merge stock options with any dynamic content
    configpath = os.path.join(binpath, 'config.py')
    if os.path.exists(configpath):
        extconfig = imp.load_source('config', configpath)
        config = utils.Attributify(extconfig)
    else:
        config = utils.Attributify(config)

    parser = OptionParser()
    parser.add_option('--data-file', dest='logs', action='append', \
            default=[], \
            help='specify memory logs to diff; at (least and most) two are ' \
                    'required')
    parser.add_option('--out-file', dest='outfile', \
            help='specify file to save results to (defaults to stdout)' \
            ' (names the binary file if --save-binary has been specified!)')
    #parser.add_option('--duplicates', action='store_true', \
    #        help='do not remove duplicates')
    parser.add_option('--trusted-pattern', dest='patterns', \
            action='append', default=[], \
            help='specify additional trusted pattern')
    parser.add_option('--save-binary', dest='savebin', default=False, \
            action='store_true', help='specify that results be saved ' \
            'in binary form (defaults to %default)')
    parser.add_option('--sym-cache', dest='symcache', \
            default=os.path.join(config.WORK_DIR, 'cache.sym'), \
            help='specify file to use for symbol caching; this will ' \
            'significantly speed symbol lookups (default is %default)')
    parser.add_option('--verbose', action='store_true', \
            help='increase output verbosity')

    if not sys.argv[1:]:
        parser.print_help()
        sys.exit(1)

    (opts, args) = parser.parse_args()
    sys.argv[:] = args

    log = logging.getLogger('umdh')
    log.addHandler(logging.StreamHandler())
    if opts.verbose:
        log.setLevel(logging.DEBUG)

    if args:
        log.debug('unqualified files=%s' % args)
    if os.path.exists(configpath):
        log.debug('using local config.py')

    datadir = utils.data_dir(config.get('WORK_DIR', binpath))
    cachefiles = [fn for fn in os.listdir(datadir) if fnmatch(fn, '.cache.py')]
    if cachefiles:
        cachefile = cachefiles.pop()
        log.debug('using cached config: %s' % cachefile)
        cachedconfig = imp.load_source('config', \
                                os.path.join(datadir, cachefile))
        cachedopts = utils.Attributify(cachedconfig)
        config.update(cachedopts)
    # in case we receive ids for log files on the command line
    # guess them by probing files in the configured working directory
    # given options from the cached config
    files = opts.logs or args
    try:
        _ids = map(int, files)
    except ValueError:
        pass
    else:
        files = [os.path.join(datadir, '%d_snapshot_%d.log' % \
                    (config.active_pid, _id)) for _id in _ids]
        log.debug('deduced file names from ids: %s' % files)

    traces = _load_backtraces(files)
    with symbols(bin_path=';'.join(config.DBG_BIN_PATHS), \
                    sym_path=';'.join(config.DBG_SYMBOL_PATHS)) as _sym:
        sym = SymProxy(_sym, opts.symcache)
        patterns = config.get('TRUSTED_PATTERNS', [])
        for p in opts.patterns:
            patterns.append(re.compile(p), re.IGNORECASE)
        modules = config.get('TRUSTED_MODULES', [])
        grepfn = filter_on_foreign_module( \
                    traces[-1], symbols=sym, \
                    trustedmodules=modules, \
                    trustedpatterns=patterns)
        # compute diff for the last two data files
        if not utils.frozen():
            pdb.set_trace()
        diff = traces[-2].diff_with(traces[-1], grepfn=grepfn)
        #if not opts.duplicates and config.REMOVE_DUPLICATES:
        if config.COMPRESS_DUPLICATES:
            try:
                level = utils.duplicate_levels[config.COMPRESS_DUPLICATES]
            except ValueError:
                log.warning('Invalid duplicate compression level: %s' \
                        % level)
            else:
                diff.compress_duplicates(level)

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
        if opts.symcache:
            sym.save()
        #sym.dump_stats()

