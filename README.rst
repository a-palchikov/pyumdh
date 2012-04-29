        pyumdh: use python to find memory leaks in your native windows apps

pyumdh is a collection of utils aimed to help in tracking memory leaks in native windows apps.
Note, taht this is not a stand-alone memory leak detector and requires the initial use of
UMDH (user mode dump heap tool) from debugging tools for windows.
UMDH is used to boostrap these scripts with the initial set of memory snapshots.

Currently, helpers the toolkit provides, fall in two main categories:
        * automating UMDH
        * analyzing memory snapshots (as in diffing and filtering)

There's a script that can optionally be packaged into an executable using the provided setup.py:
        python setup.py py2exe

It provides a no-brainer CLI interface to take memory snapshots from running processes.
Command line options:
  -h, --help            show help message and exit
  -v VERBOSE, --verbose=VERBOSE
                        increase verbosity
  --pid=PID             snapshot from process id
  --pname=PNAME         snapshot from process name
  --log-file=LOGFILE    log to file

  * Automating UMDH *
To start working with a specific process, one of --pid or --pname suffices. To continue the session,
pyumdh can be started w/o parameters - it will retrieve parameters from a cached configuration file
valid for a single process session.

  * Analyzing memory snapshots *
A collection of utilities to parse and compare the available memory snapshots provides a handy basis
for memory analysis.

Abstractions provided include: Backtraces to read/process memory snapshots (files) and Filters to help with
diffing and filtering of allocation stacks.

Stock filters include a heuristics-based search for modules of interest and a basic stack grep.
