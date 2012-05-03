
from pyumdh.backtrace import Backtrace
from unittest import TestCase, main
import os

class BacktraceParseTest(TestCase):
    def setUp(self):
        self._trace = Backtrace('test.log')

    def tearDown(self):
        if os.path.exists('test.tmp'):
            os.remove('test.tmp')

    def test_Common(self):
        self.assertEquals(len(self._trace._modules), 17)
        self.assertEquals(len(self._trace._heaps), 2)
        heap = self._trace._heaps[0x2E60000]
        self.assertEquals(len(heap), 5)
        stack = heap[0x18D0A0D0].stack
        self.assertEquals(len(stack), 32)
        self.assertEquals(len(heap[0x1AF07D3C].allocs), 3)
        self.assertEquals(len(heap[0x1AF083B4].allocs), 2)
        self.assertEquals(len(heap[0x1AF0B99C].allocs), 1)

    def test_SaveLoad(self):
        self._trace.save(r'test.tmp')
        dummy = Backtrace()
        dummy.load('test.tmp')
        self.assertEquals(len(dummy._modules), len(self._trace._modules))
        self.assertTrue(0x2E60000 in dummy._heaps)
        self.assertEquals(len(dummy._heaps[0x2E60000]), \
                            len(self._trace._heaps[0x2E60000]))

if __name__ == '__main__':
    main()
