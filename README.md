# FFRI Dataset scripts

You can make datasets like FFRI Dataset using this script.

## Requirements

- Python 3.6
- pipenv

Alternatively, you can use Docker. See [Using Docker](#Using-Docker).

## Prepare To Use

**Attention** We recommend that you run the following commands in the working directory (ffridataset-scripts directory).

```
sudo apt update
sudo apt install wget git gcc g++ make autoconf libfuzzy-dev unar cmake mlocate python3 python3-pip python3-dev libssl1.0.0 libssl-dev python3-setuptools

pipenv shell
pipenv sync
pip install dist_lief/lief-0.11.0.ffridataset2020-cp36-none-linux_x86_64.whl

git clone https://github.com/trendmicro/tlsh.git
cd tlsh
git checkout 4.2.1
./make.sh
cd py_ext
python ./setup.py install
cd ../..

wget mark0.net/download/trid_linux_64.zip
unar trid_linux_64.zip
cp trid_linux_64/trid ./
chmod u+x trid
cp triddefs_dir/triddefs-dataset2020.trd triddefs.trd
```

### Run Tests

**Attention** Do not store a file named test.exe in the working directory. The test script copies testbin/test.exe in the directory and removes it.

```
python test_main.py
```

### Make A Data CSV

This script requires a csv file which contains file information such as labels, dates, file paths. For instance,

```
path,label,date
~/cleanware/a,0,
~/malware/b,1,2018/01/01
```

## How To Use

**Attention** Do not store malware and cleanware in the working directory. This script copies malware and cleanware in the directory and removes them.

```
python main.py --csv <path/to/csv> --out <path/to/output_dataset_dir> --log <path/to/log_file>
```

## Using Docker

```
docker build --tag ffridataset-scripts .
docker run -v <path/to/here>/testbin:/work/testbin ffridataset-scripts test_main.py
# Note that data directory contains a CSV file and executable files which you want to process.
docker run -v <path/to/here>/data:/work/data -v <path/to/here>/out_dir:/work/out_dir ffridataset-scripts main.py --csv ./data/target.csv --out ./out_dir --log ./dataset.log
```

When using Docker, there exist some limitations:
- file paths in a CSV file should be specified as a relative path to the container's working directory. Example CSV file is as follows.

```
path,label,date
./data/cleanware/test0.exe,0,2018/01/01
./data/malware/test1.exe,1,2018/01/02
```

- Mount the host directory which contains both a csv file and executable files to the container's `/work/data`.
- Mount the host directory in which you want to output JSON files to the container's `/work/out_dir`.

## Notes about hashes

- TLSH can be an empty string. This is because a file must have a sufficient amount of complexity to produce valid TLSH. See https://github.com/trendmicro/tlsh/blob/master/README.md for more details.
- peHashes (crits, endgame, and totalhash) can be null due to their implementation bugs.

## Notes about TrID definition file

- TrID definition files included in [triddefs\_dir](triddefs_dir) are redistributed with the permission from the TrID author, Marco Pontello.
- The latest definition file can be obtained from the [TrID website](https://mark0.net/soft-trid-e.html).

## Notes about LIEF

- This script uses the [patched version of LIEF](https://github.com/kohnakagawa/LIEF/tree/dev/ffri-dataset).
- This LIEF is redistributed under [Apache-2.0 LICENSE](third-party-licenses/LIEF) as [whl file](dist_lief/lief-0.11.0.ffridataset2020-cp36-none-linux_x86_64.whl).

## TESTED

- Ubuntu 18.04 on WSL on Windows 10 Pro 1803
- Ubuntu 18.04.3 LTS

## Author

Yuki Mogi. &copy; FFRI, Inc. 2019

Koh M. Nakagawa. &copy; FFRI, Inc. 2019
