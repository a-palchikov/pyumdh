
import py2exe
import sys
from distutils.core import setup

options = {'py2exe': \
		{
			'excludes': ['Tkinter', 'tcl'],
			'dll_excludes': ['w9xpopen.exe'],
            'bundle_files': 3
		}
}
setup(
	name = 'pyumdh',
	console=[r'pyumdh\pyumdh.py'],
	version = '0.0.1',
	description = 'automates umdh and provides useful abstractions to help with backtrace analysis',
	author = 'deemok@gmail.com',
	options = options,
	zipfile = None
)

