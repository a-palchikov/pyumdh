# vim:ts=4:sw=4:expandtab
"""!heap -stat output parser"""

import re
import sys
from functools import partial
import cPickle as pickle
import pdb
from pprint import pprint as pp
from pyumdh.utils import fmt_size

def print_stats(item):
    return '{0:8X}h {1:8} - {2:10X}h'.format(item[2], item[1], item[0])


alloc_re = re.compile(r'([0-9A-Fa-f]+) ([0-9A-Fa-f]+) ([0-9A-Fa-f]+)\s+' \
        '\[([0-9A-Fa-f]+)\]\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+) - \(busy\)')

if __name__ == '__main__':
    allocs = {}
    fromhex = partial(int, base=16)
    with open(sys.argv[1], 'r') as f:
        for line in f:
            m = alloc_re.search(line)
            if m:
                entry, size, prev, flags, userptr, usersize = map(fromhex, \
                        m.group(1, 2, 3, 4, 5, 6))
                a = allocs.setdefault(usersize, [0, [], size])
                a[0] += 1
                a[1].append(entry)
    print 'Allocations by size:'
    pp(map(hex, sorted(allocs, reverse=True)))
    print 'Total size: %s' % fmt_size(sum(a*b[0] for a, b in allocs.iteritems()))
    #print map(hex, sorted([a*b[0] for a, b in allocs.iteritems()], reverse=True))

    foo = sorted([(a*b[0],b[0],a) for a, b in allocs.iteritems()], reverse=True)
    print '{:8} {:8} - {:10}'.format('size', '#blocks', 'total')
    print('\n'.join(map(print_stats, foo)))

    if sys.argv[2:]:
        with open(sys.argv[2], 'wb') as f:
            pickle.dump(allocs, f)

