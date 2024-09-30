import unittest
import os
import subprocess
import string
from parameterized import parameterized

def gen_check(data, off):
    return data[:off] + data[off+1:]

class TestEraser(unittest.TestCase):
    FNAME = '.test'
    
    def tearDown(self):
        os.remove(TestEraser.FNAME)
        os.remove("/tmp/.eraser")
    
    def _prep_file(self, data):
        with open(TestEraser.FNAME, "wt") as f:
            f.write(data)
    
    def _read_file(self):
        data = ''
        with open(TestEraser.FNAME, "rt") as f:
            data = f.read()
        
        return data
    
    def _run_eraser(self, input, offset):
        self._prep_file(input)
        output = subprocess.check_output(['./eraser', TestEraser.FNAME, str(offset)])
        return self._read_file()

    @parameterized.expand([
        ("0123456789", 0),
        ("0123456789", 1),
        ("0123456789", 9),
        ("0", 0),
        (string.digits * 0x1000, 5000),
        (string.digits * 256, (len(string.digits) * 256)-1),
        (string.digits * 256, 0),
    ])
    def test_empty_file(self, raw, offset):
        self.assertEqual(self._run_eraser(raw, offset), gen_check(raw, offset))


if __name__ == '__main__':
    unittest.main()
