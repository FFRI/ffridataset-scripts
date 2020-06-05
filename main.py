#!/usr/bin/python3
"""
Author of this code work, Yuki Mogi. c FFRI, Inc. 2019
Author of this code work, Koh M. Nakagawa. c FFRI, Inc. 2020
"""

import tlsh
import ssdeep
import pefile
import pehash
import pyimpfuzzy
import lief
import json
import subprocess
import hashlib
import pandas as pd
import numpy as np
import os
import argparse
import traceback
import yara
import logzero
import errno
import sys
import shutil
from logzero import logger
from pypeid import PEiDScanner


class Scanner:
    def __init__(self, logger):
        self.__logger = logger

    def register_scanners(self, scanners):
        self.__scanners = scanners

    def scan(self, path):
        args = {}
        for key, scanner in self.__scanners.items():
            try:
                if scanner["method"] is None:
                    method = lambda x: x
                else:
                    method = scanner["method"]
                if scanner["next"] is None:
                    next_method = lambda x: x
                else:
                    next_method = scanner["next"]
                args.update({key: method(path)})
                next_method(args)
            except:
                self.__logger.warning(f"in scanning {key}, {traceback.format_exc()}")
                raise RuntimeError("Scan failed")
        return args


class Computer:
    def __init__(self, scanner, logger, error_mode="ignore"):
        self.__error_mode = error_mode
        self.__logger = logger
        self.__scanner = scanner

    def register_computers(self, computers):
        self.__computers = computers

    def run(self, orig_path, out_dir, optional_args=None):
        self.__logger.info(f"processing {orig_path}")

        path = os.path.basename(orig_path)
        try:
            shutil.copyfile(orig_path, path)
        except shutil.SameFileError as e:
            self.__logger.error("DO NOT STORE MALWARE AND CLEANWARE IN THE WORKING DIRECTORY")
            self.__logger.error("See README.md for detail")
            raise e

        try:
            args = self.__scanner.scan(path)
        except RuntimeError:
            os.remove(path)
            return
        except:
            self.__logger.warning(
                f"scan failed. path:{orig_path}, {traceback.format_exc()}"
            )
            os.remove(path)
            return

        if optional_args is not None:
            args.update(optional_args)

        def execute(args_dict, args, method):
            try:
                if isinstance(args, list):
                    dict_arg = {k: args_dict[k] for k in args}
                    return dict_arg if method is None else method(dict_arg)
                else:
                    return (
                        args_dict[args] if method is None else method(args_dict[args])
                    )
            except OSError as err:
                self.__logger.error(traceback.format_exc())
                if err.errno == errno.ENOMEM:
                    self.__logger.error("Cannot allocate memory exception is thrown")
                    self.__logger.error("This may occur due to memory leak problems of LIEF")
                    self.__logger.error("So this process exits")
                    self.__logger.error(f"Processed file {orig_path}")
                    os.remove(path)
                    raise err
            except:
                self.__logger.warning(
                    f"Exception is thrown. path:{orig_path}, {traceback.format_exc()}"
                )
                if self.__error_mode == "skip":
                    self.__logger.warning(f"skipping. path:{orig_path}")
                    os.remove(path)
                    raise RuntimeError("Computing failed")
                return None

        result = {
            k: execute(args, v["args"], v["method"])
            for k, v in self.__computers.items()
        }
        os.remove(path)
        result.update(id=result["hashes"]["sha256"])
        with open(os.path.join(out_dir, result["id"] + ".json"), "w") as fout:
            fout.write(json.dumps(result) + "\n")


def open_file(path):
    with open(path, "rb") as f:
        sample = f.read()
    pe = pefile.PE(data=sample)
    return {"sample": sample, "pe": pe}


def format_sample_and_pe(dict_to_format):
    sample_and_pe = dict_to_format.pop("sample_and_pe")
    dict_to_format.update(sample=sample_and_pe["sample"], pe=sample_and_pe["pe"])


class PEDetector:
    def __init__(self, logger):
        self.__rule = yara.compile(
            source="rule pe { condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }"
        )
        self.__logger = logger

    def is_pe_file(self, path):
        is_pe_file_value = self.__rule.match(path) != []
        if not is_pe_file_value:
            self.__logger.warning(f"{path} is not a PE file. It will be skipped.")
        return is_pe_file_value


def compute_trid(path):
    trid_list = (
        subprocess.run(
            ["./trid", os.path.basename(path)], stdout=subprocess.PIPE, check=True
        )
        .stdout.decode("utf-8")
        .split("\n")[6:-1]
    )
    result = {"".join(i.split()[1:]): i.split()[0] for i in trid_list}
    return result


def get_strings(path):
    result = (
        subprocess.run(["strings", path], stdout=subprocess.PIPE, check=True)
        .stdout.decode("utf-8")
        .split("\n")[:-1]
    )
    return result


def compute_lief(path):
    return json.loads(lief.to_json(lief.PE.parse(path)))


def compute_hashes(dict_arg):
    return compute_hashes_impl(**dict_arg)


def compute_hashes_impl(sample, pe):
    md5_value = hashlib.md5(sample).hexdigest()
    sha1_value = hashlib.sha1(sample).hexdigest()
    sha256_value = hashlib.sha256(sample).hexdigest()
    ssdeep_value = ssdeep.hash(sample)
    impfuzzy_value = pyimpfuzzy.get_impfuzzy_data(sample)
    tlsh_value = tlsh.hash(sample)
    totalhash = pehash.totalhash_hex(pe=pe)
    anymaster = pehash.anymaster_hex(pe=pe)
    anymaster_v1_0_1 = pehash.anymaster_v1_0_1_hex(pe=pe)
    endgame = pehash.endgame_hex(pe=pe)
    crits = pehash.crits_hex(pe=pe)
    pehashng = pehash.pehashng_hex(pe=pe)
    imphash = pe.get_imphash()

    return {
        "md5": md5_value,
        "sha1": sha1_value,
        "sha256": sha256_value,
        "ssdeep": ssdeep_value,
        "imphash": imphash,
        "impfuzzy": impfuzzy_value,
        "tlsh": tlsh_value,
        "totalhash": totalhash,
        "anymaster": anymaster,
        "anymaster_v1_0_1": anymaster_v1_0_1,
        "endgame": endgame,
        "crits": crits,
        "pehashng": pehashng,
    }


def get_filesize(path):
    return os.stat(path).st_size


def main():
    parser = argparse.ArgumentParser(
        description="Make a dataset like FFRI Dataset!"
    )
    parser.add_argument("--csv", required=True, help="<path/to/csv>")
    parser.add_argument("--out", required=True, help="<path/to/output_dataset_dir>")
    parser.add_argument(
        "--error_mode",
        default="ignore",
        choices=["ignore", "skip"],
        help="ignore: non critical errors will be ignored. skip: if an error occured, the file will be skipped. default: ignore",
    )
    parser.add_argument("--log", required=True, help="<path/to/log_file>")
    args = parser.parse_args()
    df = pd.read_csv(args.csv)

    logzero.logfile(args.log)
    pe_detector = PEDetector(logger)
    pe_scanner = Scanner(logger)
    scanners = {
        "path": {"method": None, "next": None},
        "sample_and_pe": {"method": open_file, "next": format_sample_and_pe},
    }
    pe_scanner.register_scanners(scanners)

    peid_scanner = PEiDScanner(logger)

    pe_computer = Computer(pe_scanner, logger, args.error_mode)
    computers = {
        "label": {"method": None, "args": "label"},
        "date": {
            "method": lambda x: x if x is not None and x == x else None,
            "args": "date",
        },
        "file_size": {"method": get_filesize, "args": "path"},
        "hashes": {"method": compute_hashes, "args": ["sample", "pe"]},
        "lief": {"method": compute_lief, "args": "path"},
        "peid": {"method": peid_scanner.scan_file, "args": "path"},
        "trid": {"method": compute_trid, "args": "path"},
        "strings": {"method": get_strings, "args": "path"},
    }
    pe_computer.register_computers(computers)

    logger.info("main start")

    for index, row in df.iterrows():
        try:
            if not pe_detector.is_pe_file(row.path):
                logger.warning(f"{row.path} is not PE file. So skip this.")
                continue
            pe_computer.run(row.path, args.out, {"label": row.label, "date": row.date})
        except OSError:
            sys.exit(os.EX_SOFTWARE)
        except RuntimeError:
            continue
        except:
            logger.error(traceback.format_exc())
            continue

    logger.info("main end")


if __name__ == "__main__":
    main()
