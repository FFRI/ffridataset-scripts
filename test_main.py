#
# (c) FFRI Security, Inc., 2019-2023 / Author: FFRI Security, Inc.
#
import json
import os
import shutil
import unittest
from unittest import mock

import pefile
from pypeid import PEiDScanner
from typer.testing import CliRunner

import main

dir_path = "testbin"
bin_pe_path = os.path.join(dir_path, "test.exe")
bin_nonpe_path = os.path.join(dir_path, "test.csv")
with open(bin_pe_path, "rb") as f:
    sample = f.read()
with open(bin_nonpe_path, "rb") as f:
    sample_nonpe = f.read()
bin_pe = pefile.PE(data=sample)
bin_packed_path = os.path.join(dir_path, "test_upx.exe")
txt_path = os.path.join(dir_path, "test_lief.json")
def read_json(path: str):
    with open(os.path.join(dir_path, path)) as f:
        obj = json.load(f)
    return obj

runner = CliRunner()



class TestMain(unittest.TestCase):
    def test_get_strings_pe(self):
        actual = main.get_strings(bin_pe_path)
        expected = read_json("test_strings_pe.json")
        self.assertEqual(expected, actual)

    def test_get_strings_nonpe(self):
        actual = main.get_strings(bin_nonpe_path)
        expected = read_json("test_strings_nonpe.json")
        self.assertEqual(expected, actual)

    def test_compute_lief_pe(self):
        actual = main.compute_lief({"path": bin_pe_path, "pe": bin_pe})
        expected = read_json("test_lief_pe.json")
        self.assertEqual(expected, actual)

    def test_compute_lief_nonpe(self):
        actual = main.compute_lief({"path": bin_pe_path, "pe": None})
        expected = None
        self.assertEqual(expected, actual)

    def test_compute_hashes_pe(self):
        pe = pefile.PE(data=sample)
        actual = main.compute_hashes({"pe": pe, "sample": sample})
        expected = read_json("test_hashes_pe.json")
        self.assertEqual(expected, actual)

    def test_compute_hashes_nonpe(self):
        actual = main.compute_hashes({"pe": None, "sample": sample_nonpe})
        expected = read_json("test_hashes_nonpe.json")
        self.assertEqual(expected, actual)

    def test_get_filesize_pe(self):
        actual = main.get_filesize(bin_pe_path)
        expected = 12288
        self.assertEqual(expected, actual)

    def test_get_filesize_nonpe(self):
        actual = main.get_filesize(bin_nonpe_path)
        expected = 46
        self.assertEqual(expected, actual)

    def test_compute_peid_pe(self):
        peid_scanner = PEiDScanner()
        actual = peid_scanner.scan_file(bin_pe_path)
        expected = read_json("test_peid_pe.json")
        self.assertEqual(expected, actual)

    def test_compute_trid_pe(self):
        path = os.path.basename(bin_pe_path)
        shutil.copyfile(bin_pe_path, path)
        actual = main.compute_trid(path)
        os.remove(path)
        expected = read_json("test_trid_pe.json")
        self.assertEqual(expected, actual)

    def test_pe_detect_pe(self):
        logger = mock.MagicMock()
        pe_detector = main.PEDetector(logger)
        self.assertTrue(pe_detector.is_pe_file(bin_pe_path))
        self.assertFalse(pe_detector.is_pe_file(txt_path))

    def test_get_die_pe(self):
        path = os.path.basename(bin_pe_path)
        shutil.copyfile(bin_pe_path, path)
        actual = main.compute_die(path)
        os.remove(path)
        expected = read_json("test_die_pe.json")
        self.assertEqual(expected, actual)

    def test_compute_manalyze_pe(self):
        path = os.path.basename(bin_packed_path)
        shutil.copyfile(bin_packed_path, path)
        actual = main.compute_manalyze({"path": path, "pe": bin_pe})
        os.remove(path)
        expected = read_json("test_manalyze_pe.json")
        self.assertEqual(expected, actual)

    def test_compute_manalyze_nonpe(self):
        path = os.path.basename(bin_nonpe_path)
        shutil.copyfile(bin_nonpe_path, path)
        actual = main.compute_manalyze({"path": path, "pe": None})
        os.remove(path)
        expected = None
        self.assertEqual(expected, actual)

    def test_cli_pe(self):
        result = runner.invoke(
            main.app,
            [
                "--csv",
                "./testbin/test.csv",
                "--out",
                "./out_dir",
                "--error-mode",
                "skip",
                "--log",
                "test.log",
                "--ver",
                "v2021",
            ],
        )
        assert result.exit_code == 0

    def test_cli_nonpe(self):
        result = runner.invoke(
            main.app,
            [
                "--csv",
                "./testbin/test.csv",
                "--out",
                "./out_dir",
                "--error-mode",
                "skip",
                "--log",
                "test.log",
                "--ver",
                "v2021",
                "--not-pe-only",
            ],
        )
        assert result.exit_code == 0

if __name__ == "__main__":
    unittest.main()
