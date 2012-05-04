
import py2exe
import sys
from distutils.core import setup
from glob import glob

datafiles = [('x64', glob('pyumdh\\x64\\*.dll')), \
            ('x86', glob('pyumdh\\x86\\*.dll')), \
            ('', glob('pyumdh\\config.py')) \
            ]
options = {'py2exe': \
		{
			'excludes': ['Tkinter', 'tcl'],
			'dll_excludes': ['w9xpopen.exe'],
            'bundle_files': 3
		}
}
setup(
	name = 'differ',
	console = [r'pyumdh\differ.py'],
    data_files = datafiles,
	version = '0.0.1',
	description = 'memory snapshot differ',
	author = 'deemok@gmail.com',
	options = options,
	zipfile = None
)

