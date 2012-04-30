
from pyumdh.backtrace import Backtrace
from unittest import TestCase, main
import pdb

class BacktraceParseTest(TestCase):
    def setUp(self):
        self._trace = Backtrace('test.log')
    def tearDown(self):
        pass
    def test_Common(self):
        self.assertEquals(len(self._trace._modules), 17)
        self.assertEquals(len(self._trace._heaps), 2)
        heap = self._trace._heaps[0x2E60000]
        self.assertEquals(len(heap), 5)
        stack = heap['18D0A0D0'].stack
        self.assertEquals(len(stack), 32)
        #pdb.set_trace()
        self.assertEquals(len(heap['1AF07D3C'].allocs), 3)
        self.assertEquals(len(heap['1AF083B4'].allocs), 2)
        self.assertEquals(len(heap['1AF0B99C'].allocs), 1)

if __name__ == '__main__':
    main()
