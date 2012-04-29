# basic umdh configuration
import re

# Path to debugging tools for windows installation
# Used for tool lookup (UMDH, tlist)
# Make sure to match the architecture of the application you're troubleshooting
# with that of debugging tools (32bits vs 64bits) - these must match for
# memory snapshots to work
# 32bits
# DBG_TOOLS_PATH = 'path\\to\\debugging\\tools\\for\\windows'
# 64bits
#DBG_TOOLS_PATH=r'C:\Program Files\Debugging Tools for Windows (x64)'
DBG_TOOLS_PATH = ''

# List of symbol paths
# You can also include symbol server style paths if symsrv.dll is available
#DBG_SYMBOL_PATHS = ['srv*path\\to\\symbol\\store*http://msdl.microsoft.com/download/symbols']
DBG_SYMBOL_PATHS = []

# Path to binaries used by symbol provider
#DBG_BIN_PATHS = ['path\\to\\your\\application']
DBG_BIN_PATHS = []

# If True, will automatically launch analysis session when two snapshots
# are available
# FIXME todo
#AUTO_LAUNCH = True

# Specifies the directory for logs and intermediate cache files
# Can be specified in relative form - in which case it's created relative to
# the script's bin path
WORK_DIR = 'data'

# Stack frames with these patterns matched will be skipped from diff/dump
# Note, the setting is crrent effective only in backtrace.py when it's
# used as main program
# FIXME Replace with patterns that suit your needs before using it!
TRUSTED_PATTERNS = [re.compile(r'qtgui4!qfontenginewin::recalcAdvances', \
                        re.IGNORECASE), \
                    re.compile(r'qtcore4!_hb_alloc', re.IGNORECASE), \
                    re.compile(r'qtcore4!HB_OpenTypeShape', re.IGNORECASE), \
                    re.compile(r'qt(:?core|gui)4!QVector<[^>]+>::realloc', \
                        re.IGNORECASE), \
                    re.compile(r'qtgui4!QTextLayout::draw', re.IGNORECASE)]

# These are modules making allocations that we choose to skip during diff/dump
# If specified, these take precedence over TRUSTED_PATTERNS
# FIXME Replace with patterns that suit your needs before using it!
TRUSTED_MODULES = ['dbghelp.dll']
