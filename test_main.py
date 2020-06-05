import unittest
from unittest import mock
import main
import json
import os
import pefile
import shutil
from pypeid import PEiDScanner


dir_path = "testbin"
bin_path = os.path.join(dir_path, "test.exe")
txt_path = os.path.join(dir_path, "test_lief.json")


class TestMain(unittest.TestCase):
    def test_get_strings(self):
        actual = main.get_strings(bin_path)
        with open(os.path.join(dir_path, "test_strings.json")) as f:
            expected = json.load(f)
        self.assertEqual(expected, actual)

    def test_compute_lief(self):
        actual = main.compute_lief(bin_path)
        with open(os.path.join(dir_path, "test_lief.json")) as f:
            expected = json.load(f)
        self.assertEqual(expected, actual)

    def test_compute_hashes(self):
        with open(bin_path, "rb") as f:
            sample = f.read()
        pe = pefile.PE(data=sample)
        actual = main.compute_hashes({"pe": pe, "sample": sample})
        with open(os.path.join(dir_path, "test_hashes.json")) as f:
            expected = json.load(f)
        self.assertEqual(expected, actual)

    def test_get_filesize(self):
        actual = main.get_filesize(bin_path)
        expected = 12288
        self.assertEqual(expected, actual)

    def test_compute_peid(self):
        peid_scanner = PEiDScanner()
        actual = peid_scanner.scan_file(bin_path)
        with open(os.path.join(dir_path, "test_peid.json")) as f:
            expected = json.load(f)
        self.assertEqual(expected, actual)

    def test_compute_trid(self):
        path = os.path.basename(bin_path)
        shutil.copyfile(bin_path, path)
        actual = main.compute_trid(path)
        os.remove(path)
        with open(os.path.join(dir_path, "test_trid.json")) as f:
            expected = json.load(f)
        self.assertEqual(expected, actual)

    def test_pe_detect(self):
        logger = mock.MagicMock()
        pe_detector = main.PEDetector(logger)
        self.assertTrue(pe_detector.is_pe_file(bin_path))
        self.assertFalse(pe_detector.is_pe_file(txt_path))


if __name__ == "__main__":
    unittest.main()
