pyumdh: use python to find memory leaks in your native windows apps
===================================================================

pyumdh is a collection of python utils aimed to help in tracking memory leaks in native windows apps.
Note, that this is not a stand-alone memory leak detector and requires the initial use of
UMDH (user mode dump heap tool) from debugging tools for windows.
UMDH is used to bootstrap these scripts with the initial set of memory snapshots.
Also, it is a not particularly user-friendly (as in GUI) and requires heavy use of python for analysis.
I'm planning to add a basic browser-based support for viewing analysis results in the future though.

What can you do with pyumdh?
        * automate UMDH
        * diff memory logs

Provided setup.py can be used to build an executable (py2exe).

  * Automate UMDH
To start working with a specific process, one of --pid or --pname suffices. To continue the session,
pyumdh can be started w/o parameters - it will retrieve parameters from a cached configuration file
valid for a single process session.
Make sure you clean up sessions after you're done with them to avoid spurious warnings from UMDH
being unable to access process using archaic cached configuration.

  * Diff logs
Backtrace class provides a simple base for further processing of memory snapshots. Diffs are
represented as instances of Backtrace so diffing Diffs is possible.

I've implemented a basic filter to help me match traces of interest based on a notion of a system
allocator and a foreign module.

A system allocator is simply the system APIs for allocating memory. These are currently hardcoded in
filters.py.
Foreign module is one making an allocation the filter does not know about. By default, filter assumes
knowledge of system modules (based on their location) and defines foreign to be everything else.
The list of system (or trusted) modules can be configured to fit your setup.

