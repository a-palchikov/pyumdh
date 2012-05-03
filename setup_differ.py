
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
	name = 'differ',
	console=[r'pyumdh\differ.py'],
	version = '0.0.1',
	description = 'memory snapshot differ',
	author = 'deemok@gmail.com',
	options = options,
	zipfile = None
)

