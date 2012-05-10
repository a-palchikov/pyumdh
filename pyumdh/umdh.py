# umdh control panel
# Simplifies umdh by
# 	a. automatically handling UMDH's snap mode
#	b. caching command line so that repeatitive invocations are a breeze
#	c. providing rich configurability

import optparse
import os
import logging
import re
import imp
import types
import pdb
from subprocess import Popen, PIPE, check_output, CalledProcessError
from multiprocessing import Process, Pool, freeze_support
from fnmatch import fnmatch
from optparse import OptionParser
import pyumdh.utils as utils
import pyumdh.config as config


def _prelaunch_env(pypath=None):
    env = os.environ
    pythonpath = env['pythonpath']
    if pypath:
        env.update({'pythonpath': ';'.join([pypath, pythonpath])})
    subprocess.Popen([os.environ['comspec'], '/c', sys.executable], \
                    creationflags=subprocess.CREATE_NEW_CONSOLE, \
                    env=env)

def _tool_path(toolname, config):
    return os.path.join(config.DBG_TOOLS_PATH, toolname)

def _data_file(fn, config, curdir=None):
    datapath = utils.data_dir(config.get('WORK_DIR', curdir))
    return os.path.join(datapath, fn)

def _find_pid(pname, config):
    """Look up pid based on process name"""
    log = logging.getLogger('umdh')
    tool = _tool_path('tlist.exe', config)
    try:
        log.debug('looking up pid for process %s' % pname)
        pid = check_output([tool, '-p', pname]).rstrip('\r\n')
        if pid and pid != '-1':
            log.debug('pid=%s' % pid)
            return int(pid)
        raise ValueError('Unable to find process with name %s' % pname)
    except CalledProcessError:
        log.critical('unable to map process name to id - tool not found - ' \
                        '%s' % tool)

def umdh(pid, config):
    log = logging.getLogger('umdh')
    def fmt_value(value):
        if isinstance(value, basestring):
            return "'%s'" % value.replace('\\', '\\\\')
        else:
            return str(value)
    def fmt_vars(config):
        attrs = []
        for attr, value in config.iteritems():
            # FIXME mark config attrs as non-serializable?..
            if not attr.startswith('TRUSTED_') and type(value) is not \
                    types.ModuleType:
                attrs.append('%s=%s' % (attr, fmt_value(value)))
        return '\n'.join(attrs)
    tool = _tool_path('umdh.exe', config)
    pid = config.setdefault('active_pid', pid)
    data_files = config.setdefault('data_files', [])
    _id = len(data_files)
    outputfile = _data_file('%d_snapshot_%d.log' % (pid, _id), config)
    data_files.append(os.path.basename(outputfile))
    log.debug('UMDH: will save log to %s' % outputfile)
    p = Popen([tool, '-snap', str(pid), '-file', outputfile], \
            stdout=PIPE, stderr=PIPE, \
            env={'_NT_SYMBOL_PATH': ';'.join(config.DBG_SYMBOL_PATHS)})
    out, err = p.communicate()
    if out:
        log.debug('UMDH[Output]: %s' % out)
    if err:
        log.debug('UMDH[Error]: %s' % err)
    if 'Error' in err:
        raise RuntimeError('UMDH[Error]: %s' % err)
# Current session's increment
# Process id in the current session
# list of data files in this session
    cachetemplate = """
# Configuration cache for %(pid)d
# you can safely delete ths file once you're done with your debugging session
%(configtext)s
"""
    configtext = fmt_vars(config)
    with open(_data_file('.cache.py', config), 'w') as f:
        f.write(cachetemplate % locals())


def main(argv):
    parser = OptionParser()
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', \
                        help='increase verbosity')
    parser.add_option('--pid', type='int', help='process id')
    parser.add_option('--pname', help='process name')
    parser.add_option('--log-file', dest='logfile',  default='pyumdh.log',  \
            help='log file (default is %default)')
    opts, args = parser.parse_args(argv)

    binpath = utils.module_path()
    # load configuration and map its contents to a dict so that we could later
    # merge stock options with any dynamic content
    configpath = os.path.join(binpath, 'config.py')
    if os.path.exists(configpath):
        extconfig = imp.load_source('config', configpath)
        configopts = utils.Dictify(extconfig)
    else:
        configopts = utils.Dictify(config)

    log = logging.getLogger('umdh')
    log.addHandler(logging.StreamHandler())
    if opts.logfile:
        log.addHandler(logging.FileHandler(opts.logfile))
    if opts.verbose:
        log.setLevel(logging.DEBUG)

    datadir = utils.data_dir(configopts.get('WORK_DIR', binpath))
    log.debug('data files are here=%s' % datadir)

    configerrors = []

    if not configopts['DBG_BIN_PATHS']:
        log.warning('You might want to provide path to your application ' \
                    'binaries for symbol lookup to work best\n(configure ' \
                    'DBG_BIN_PATHS)')
    if not configopts['DBG_SYMBOL_PATHS']:
        log.warning('You might want to configure symbol paths for UMDH ' \
                'in DBG_SYMBOL_PATHS')
    if not configopts['DBG_TOOLS_PATH']:
        configerrors.append('You have to provide path to debugging tools for ' \
                'windows in DBG_TOOLS_PATH')

    if configerrors:
        error = '\n'.join(configerrors)
        log.critical(error)
        print 'If it is your first time running, please take time ' \
                'to go over config.py'
        return 1

    # check if any .cache files are available
    # cache files are a handy way to continue working on a particular active
    # umdh session
    cachefiles = [fn for fn in os.listdir(datadir) if fnmatch(fn, '.cache.py')]

    if not cachefiles and not opts.pid and not opts.pname:
        print 'Specify either process name or process id'
        parser.print_help()
        return 2

    if opts.pid or opts.pname:
        # if only process name has been specified, look up its pid
        pid = opts.pid or _find_pid(opts.pname, configopts)
    elif cachefiles:
        # currently, it makes sense to only handle a single cache file
        # i.e. file for the current session
        fn = cachefiles.pop()
        cachedconfig = imp.load_source('config', os.path.join(datadir, fn))
        cachedopts = utils.Dictify(cachedconfig)
        configopts.update(cachedopts)
        pid = int(configopts['active_pid'])
    umdh(pid, configopts)
    return 0

if __name__ == '__main__':
    import sys
    freeze_support()
    sys.exit(main(sys.argv))
