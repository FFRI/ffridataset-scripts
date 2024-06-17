#!/usr/bin/python3
#
# (c) FFRI Security, Inc., 2019-2024 / Author: FFRI Security, Inc.
#
import errno
import hashlib
import json
import os
import shutil
import subprocess
import sys
import traceback
from enum import Enum
from typing import Any, Callable, List, Dict
from logging import Logger

import lief
import pandas as pd
import pefile
import pehash
import pyimpfuzzy
import ssdeep
import typer
import yara
from loguru import logger
from pypeid.scanner import PEiDScanner
from joblib import Parallel, delayed
import tlsh

app = typer.Typer()


class ErrorMode(str, Enum):
    ignore = "ignore"
    skip = "skip"


class ErrorWrapper:
    def __init__(self, value: Any, is_left: bool):
        self.__value = value
        self.__is_left = is_left

    def is_left(self):
        return self.__is_left

    def unwrap(self):
        return self.__value


class Right(ErrorWrapper):
    def __init__(self, value: Any):
        super().__init__(value, False)


class Left(ErrorWrapper):
    def __init__(self, value: Any):
        super().__init__(value, True)


class LeftWithOS(ErrorWrapper):
    def __init__(self, value: Any):
        super().__init__(value, True)


def try_catch_with_traceback(func: Callable[[], Any]):
    try:
        return Right(func())
    except OSError as e:
        return LeftWithOS({"traceback": traceback.format_exc(), "error": e})
    except Exception as e:
        return Left({"traceback": traceback.format_exc(), "error": e})


def unify_dict(list_of_dicts: List[Dict[Any, Any]]):
    result: Dict[Any, Any] = {}
    for d in list_of_dicts:
        result.update(d)
    return result


class Scanner:
    def __init__(self, logger_: Logger):
        self.__logger = logger_

    def register_scanners(self, scanners):
        self.__scanners = scanners

    def scan(self, path: str):
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
    def __init__(
        self, scanner: Scanner, logger: Logger, error_mode: ErrorMode = ErrorMode.ignore
    ):
        self.__error_mode = error_mode
        self.__logger = logger
        self.__scanner = scanner

    def register_computers(self, computers):
        self.__computers = computers

    def run(self, orig_path: str, out_dir: str, optional_args=None):
        self.__logger.info(f"processing {orig_path}")

        path = os.path.basename(orig_path)
        try:
            shutil.copyfile(orig_path, path)
        except shutil.SameFileError as e:
            self.__logger.error(
                "DO NOT STORE MALWARE AND CLEANWARE IN THE WORKING DIRECTORY"
            )
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
            if isinstance(args, list):
                dict_arg = {k: args_dict[k] for k in args}
                return dict_arg if method is None else method(dict_arg)
            else:
                return args_dict[args] if method is None else method(args_dict[args])

        def handle_errors(left_values):
            self.__logger.warning("Some errors occurred")
            for os_error in left_values:
                if type(os_error) == LeftWithOS:
                    if os_error.unwrap()["error"].errno == errno.ENOMEM:
                        self.__logger.error(
                            "Cannot allocate memory exception is thrown"
                        )
                        self.__logger.error(
                            "This may occur due to memory leak problems of LIEF"
                        )
                        self.__logger.error("So this process exits")
                        self.__logger.error(f"Processed file {orig_path}")
                        os.remove(path)
                        raise os_error.unwrap()["error"]
                    self.__logger.warning(
                        f"Exception is thrown. path:{orig_path}, {os_error.unwrap()['traceback']}"
                    )
                else:
                    self.__logger.warning(
                        f"Exception is thrown. path:{orig_path}, {os_error.unwrap()['traceback']}"
                    )
                    if self.__error_mode == ErrorMode.skip:
                        self.__logger.warning(f"skipping. path:{orig_path}")
                        os.remove(path)
                        raise RuntimeError("Computing failed")

        def handle_wrapped_result(wrapped_result):
            wrapped_values = wrapped_result.values()
            left_values = [
                wrapped_value
                for wrapped_value in wrapped_values
                if wrapped_value.is_left()
            ]
            if not left_values:
                return {k: v.unwrap() for k, v in wrapped_result.items()}
            handle_errors(left_values)
            return {
                k: v.unwrap() if not v.is_left() else None
                for k, v in wrapped_result.items()
            }

        def execute_wrapped(k, v):
            return {
                k: try_catch_with_traceback(
                    lambda: execute(args, v["args"], v["method"])
                )
            }

        wrapped_result_list = Parallel(n_jobs=2, backend="threading")(
            [delayed(execute_wrapped)(k, v) for k, v in self.__computers.items()]
        )
        wrapped_result = unify_dict(wrapped_result_list)
        result = handle_wrapped_result(wrapped_result)

        os.remove(path)
        result.update(id=result["hashes"]["sha256"])
        with open(os.path.join(out_dir, result["id"] + ".json"), "w") as fout:
            fout.write(json.dumps(result) + "\n")


def open_file(path: str):
    with open(path, "rb") as f:
        sample = f.read()
    try:
        pe = pefile.PE(data=sample)
    except:
        pe = None
    return {"sample": sample, "pe": pe}

def format_sample_and_pe(dict_to_format: Dict[Any, Any]):
    sample_and_pe = dict_to_format.pop("sample_and_pe")
    dict_to_format.update(sample=sample_and_pe["sample"], pe=sample_and_pe["pe"])


class PEDetector:
    def __init__(self, logger_: Logger):
        self.__rule = yara.compile(
            source="rule pe { condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 }"
        )
        self.__logger = logger_

    def is_pe_file(self, path: str):
        is_pe_file_value = self.__rule.match(path) != []
        if not is_pe_file_value:
            self.__logger.warning(f"{path} is not a PE file. It will be skipped.")
        return is_pe_file_value



def compute_trid(path: str):
    trid_list = (
        subprocess.run(
            ["./trid", os.path.basename(path)], stdout=subprocess.PIPE, check=True
        )
        .stdout.decode("utf-8")
        .split("\n")
    )
    if any("Unknown!" in l for l in trid_list):
        return {}
    if any("file seems to be plain text/ASCII" in l for l in trid_list):
        return {}
    result = {"".join(i.split()[1:]): i.split()[0] for i in trid_list[6:-1]}
    return result


def compute_die(path: str):
    raw_output = subprocess.run(
        ["diec", "-j", os.path.basename(path)],
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.decode("utf-8")
    return json.loads(raw_output)

def compute_manalyze(args_dict):
    return compute_manalyze_impl(**args_dict)


def compute_manalyze_impl(path: str, pe):
    if pe is None:
        return None
    raw_output = subprocess.run(
        # NOTE: The information obtained by "--dump=dos" is finally ignored.
        # NOTE: The reason why we specify this flag is to avoid the bug of parsing resources in Manalyze.
        # NOTE: If Manalyze failed to parse the file, None will be returned.
        [
            "./workspace/Manalyze/bin/manalyze",
            "--dump=dos",
            "--output=json",
            "--plugins=packer",
            os.path.basename(path),
        ],
        stdout=subprocess.PIPE,
        check=True,
        errors="ignore",
    ).stdout
    json_output = json.loads(raw_output)
    if json_output == {}:
        return None
    result = list(json_output.values())[0]
    if "packer" in result["Plugins"].keys():
        packer_info = result["Plugins"]["packer"]
    else:
        packer_info = None
    return packer_info


def get_strings(path: str):
    result = (
        subprocess.run(["strings", path], stdout=subprocess.PIPE, check=True)
        .stdout.decode("utf-8")
        .split("\n")[:-1]
    )
    return result


def compute_lief(dict_arg):
    return compute_lief_impl(**dict_arg)


def compute_lief_impl(path: str, pe):
    if pe is None:
        return None
    return json.loads(lief.to_json(lief.PE.parse(path)))


def compute_hashes(dict_arg):
    return compute_hashes_impl(**dict_arg)


def compute_hashes_impl(sample, pe):
    md5_value = hashlib.md5(sample).hexdigest()
    sha1_value = hashlib.sha1(sample).hexdigest()
    sha256_value = hashlib.sha256(sample).hexdigest()
    ssdeep_value = ssdeep.hash(sample)
    impfuzzy_value = None if pe is None else pyimpfuzzy.get_impfuzzy_data(sample)
    tlsh_value = tlsh.hash(sample)
    totalhash = None if pe is None else pehash.totalhash_hex(pe=pe) 
    anymaster = None if pe is None else pehash.anymaster_hex(pe=pe)
    anymaster_v1_0_1 = None if pe is None else pehash.anymaster_v1_0_1_hex(pe=pe)
    endgame = None if pe is None else pehash.endgame_hex(pe=pe)
    crits = None if pe is None else pehash.crits_hex(pe=pe)
    pehashng = None if pe is None else pehash.pehashng_hex(pe=pe)
    imphash = None if pe is None else pe.get_imphash()

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


def get_filesize(path: str):
    return os.stat(path).st_size


@app.command()
def run(
    csv: str = typer.Option(..., help="<path/to/csv>"),
    out: str = typer.Option(..., help="<path/to/output_dataset_dir>"),
    error_mode: ErrorMode = typer.Option(
        ErrorMode.ignore,
        "--error-mode",
        help="ignore: non critical errors will be ignored. skip: if an error occured, the file will be skipped.",
    ),
    log: str = typer.Option(..., help="<path/to/log_file>"),
    ver: str = typer.Option(
        ..., help="version string to be included in output json file (e.g., v2022)."
    ),
    not_pe_only: bool = typer.Option(False, "--not-pe-only", help="Enable to run this script against non-pe file. Use 'ignore' as error_mode.")
) -> None:
    df = pd.read_csv(csv)

    ver_str = ver
    logger.add(log)
    pe_detector = PEDetector(logger)
    pe_scanner = Scanner(logger)
    scanners = {
        "path": {"method": None, "next": None},
        "sample_and_pe": {"method": open_file, "next": format_sample_and_pe},
    }
    pe_scanner.register_scanners(scanners)

    peid_scanner = PEiDScanner(logger)

    pe_computer = Computer(pe_scanner, logger, error_mode)
    computers = {
        "label": {"method": None, "args": "label"},
        "date": {
            "method": lambda x: x if x is not None and x == x else None,
            "args": "date",
        },
        "version": {"method": None, "args": "version"},
        "file_size": {"method": get_filesize, "args": "path"},
        "hashes": {"method": compute_hashes, "args": ["sample", "pe"]},
        "lief": {"method": compute_lief, "args": ["path", "pe"]},
        "peid": {"method": peid_scanner.scan_file, "args": "path"},
        "trid": {"method": compute_trid, "args": "path"},
        "die": {"method": compute_die, "args": "path"},
        "manalyze_plugin_packer": {"method": compute_manalyze, "args": ["path", "pe"]},
        "strings": {"method": get_strings, "args": "path"},
    }
    pe_computer.register_computers(computers)

    logger.info("main start")

    for index, row in df.iterrows():
        try:
            if (not not_pe_only) and (not pe_detector.is_pe_file(row.path)):
                logger.warning(f"{row.path} is not PE file. So skip this.")
                continue
            pe_computer.run(
                row.path,
                out,
                {"label": row.label, "date": row.date, "version": ver_str},
            )
        except OSError:
            sys.exit(os.EX_SOFTWARE)
        except RuntimeError:
            continue
        except KeyboardInterrupt:
            logger.error(traceback.format_exc())
            sys.exit(os.EX_SOFTWARE)
        except:
            logger.error(traceback.format_exc())
            continue

    logger.info("main end")


if __name__ == "__main__":
    app()