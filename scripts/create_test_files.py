#
# (c) FFRI Security, Inc., 2021-2024 / Author: FFRI Security, Inc.
#
import subprocess
import json
import shutil
import os
import hashlib
import ssdeep
import tlsh
import lief
import pyimpfuzzy
import pehash
import pefile
from pypeid import PEiDScanner

def dump_json(obj: dict, path: str):
    with open(path, 'w') as f:
        json.dump(obj, f, indent=2)

def create_die_pe(path: str):
    raw_output = subprocess.run(
        ["diec", "-j", path],
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.decode("utf-8")
    return json.loads(raw_output)

create_die_nonpe = create_die_pe

def create_trid_pe(path: str):
    shutil.copyfile(path, os.path.basename(path))
    trid_list = (
        subprocess.run(
            ["./trid", os.path.basename(path)], stdout=subprocess.PIPE, check=True
        )
        .stdout.decode("utf-8")
        .split("\n")
    )
    result = {"".join(i.split()[1:]): i.split()[0] for i in trid_list[6:-1]}
    return result

create_trid_nonpe = lambda _: {}

def create_lief_pe(path: str):
    return json.loads(lief.to_json(lief.PE.parse(path)))

create_lief_nonpe = lambda _: {}

def create_strings_pe(path: str):
    result = (
        subprocess.run(["strings", path], stdout=subprocess.PIPE, check=True)
        .stdout.decode("utf-8")
        .split("\n")[:-1]
    )
    return result

create_strings_nonpe = create_strings_pe

def create_manalyze_pe(_: str):
    raw_output = subprocess.run(
        # NOTE: The information obtained by "--dump=dos" is finally ignored.
        # NOTE: The reason why we specify this flag is to avoid the bug of parsing resources in Manalyze.
        [
            "./workspace/Manalyze/bin/manalyze",
            "--dump=dos",
            "--output=json",
            "--plugins=packer",
            "testbin/test_upx.exe",
        ],
        stdout=subprocess.PIPE,
        check=True,
        errors="ignore",
    ).stdout
    json_output = json.loads(raw_output)
    result = list(json_output.values())[0]
    if "packer" in result["Plugins"].keys():
        packer_info = result["Plugins"]["packer"]
    else:
        packer_info = None
    return packer_info

create_manalyze_nonpe = lambda _: {}

def create_peid_pe(path: str):
    peid_scanner = PEiDScanner()
    result = peid_scanner.scan_file(path)
    return result

create_peid_nonpe = lambda _: {}

def create_hashes_pe(path: str):
    with open(path, "rb") as f:
        sample = f.read()
    pe = pefile.PE(data=sample)
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

def create_hashes_nonpe(path: str):
    with open(path, "rb") as f:
        sample = f.read()
    md5_value = hashlib.md5(sample).hexdigest()
    sha1_value = hashlib.sha1(sample).hexdigest()
    sha256_value = hashlib.sha256(sample).hexdigest()
    ssdeep_value = ssdeep.hash(sample)
    impfuzzy_value = None
    tlsh_value = tlsh.hash(sample)
    totalhash = None
    anymaster = None
    anymaster_v1_0_1 = None
    endgame = None
    crits = None
    pehashng = None
    imphash = None

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


items = ["die", "hashes", "lief", "manalyze", "peid", "strings", "trid"]


def create_test_files(out_dir: str, path: str, suffix: str = "pe"):
    for item in items:
        result = eval(f"create_{item}_{suffix}")(os.path.join(out_dir, path))
        dump_json(result, f"{out_dir}/test_{item}_{suffix}.json")


if __name__ == "__main__":
    create_test_files("testbin", "test.exe")
    create_test_files("testbin", "test.csv", "nonpe")
