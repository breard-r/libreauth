from ctypes.util import find_library
from struct import Struct
from ctypes import *
from unittest import TestCase
from os import path
import sys

class TOTPcfg(Structure):
    _fields_ = [
        ('key', c_char_p),
        ('key_len', c_size_t),
        ('timestamp', c_longlong),
        ('positive_tolerance', c_ulonglong),
        ('negative_tolerance', c_ulonglong),
        ('period', c_uint),
        ('initial_time', c_ulonglong),
        ('output_len', c_size_t),
        ('output_base', c_char_p),
        ('output_base_len', c_size_t),
        ('hash_function', c_int),
    ]

class TestOTP(TestCase):
    def setUp(self):
        self.sha1 = 1
        self.sha256 = 2
        self.sha512 = 3
        channel = 'debug'
        current_file = path.abspath(__file__)
        base_dir = path.dirname(path.dirname(current_file))
        self.lib_path = path.join(base_dir, 'target', channel, 'liblibreauth.so')

    def test_totp(self):
        key = b'12345678901234567890'
        lib = cdll.LoadLibrary(self.lib_path)
        cfg = TOTPcfg()

        ret = lib.libreauth_totp_init(byref(cfg))
        self.assertEqual(ret, 0)
        self.assertIsNone(cfg.key)
        self.assertEqual(cfg.key_len, 0)
        self.assertNotEqual(cfg.timestamp, 0)
        self.assertEqual(cfg.positive_tolerance, 0)
        self.assertEqual(cfg.negative_tolerance, 0)
        self.assertEqual(cfg.period, 30)
        self.assertEqual(cfg.initial_time, 0)
        self.assertEqual(cfg.output_len, 6)
        self.assertIsNone(cfg.output_base)
        self.assertEqual(cfg.output_base_len, 0)
        self.assertEqual(cfg.hash_function, self.sha1)

        cfg.key_len = len(key)
        cfg.key = c_char_p(key)
        code = create_string_buffer(b'\000' * cfg.output_len)
        ret = lib.libreauth_totp_generate(byref(cfg), code)
        self.assertEqual(ret, 0)

        try:
            code = str(code.value, encoding="utf-8")
        except TypeError:
            code = str(code.value)
        self.assertEqual(len(code), 6)

if __name__ == '__main__':
    unittest.main()
