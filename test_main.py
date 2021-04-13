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
bin_path = os.path.join(dir_path, "test.exe")
bin_packed_path = os.path.join(dir_path, "test_upx.exe")
txt_path = os.path.join(dir_path, "test_lief.json")
runner = CliRunner()


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

    def test_get_die(self):
        path = os.path.basename(bin_path)
        shutil.copyfile(bin_path, path)
        actual = main.compute_die(path)
        os.remove(path)
        with open(os.path.join(dir_path, "test_die.json")) as f:
            expected = json.load(f)
        self.assertEqual(expected, actual)

    def test_compute_manalyze(self):
        path = os.path.basename(bin_packed_path)
        shutil.copyfile(bin_packed_path, path)
        actual = main.compute_manalyze(path)
        os.remove(path)
        with open(os.path.join(dir_path, "test_manalyze.json")) as f:
            expected = json.load(f)
        self.assertEqual(expected, actual)

    def test_cli(self):
        result = runner.invoke(
            main.app,
            [
                "--csv",
                "./testbin/test.csv",
                "--out",
                "./out_dir",
                "--error_mode",
                "skip",
                "--log",
                "test.log",
                "--ver",
                "v2021",
            ],
        )
        assert result.exit_code == 0


if __name__ == "__main__":
    unittest.main()
