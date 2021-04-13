# FFRI Dataset scripts

You can make datasets like FFRI Dataset using this script.

## Requirements

We recommend that you use Docker for making datasets. See [Using Docker](#Using-Docker) for more details.

Alternatively, you can use this script by installing the following dependencies on [tested platforms](#Tested).
See [Run this script natively](#Run-This-Script-Natively) for more details.

- Python 3.8
- [Poetry](https://python-poetry.org/)

## Using Docker

### Make A CSV File

This script requires a CSV file which contains file information such as labels, dates, file paths. For instance,

```
path,label,date
./data/cleanware/test0.exe,0,2018/01/01
./data/malware/test1.exe,1,2018/01/02
```

Note that file paths in a CSV file should be specified as relative paths to the container's working directory.

### Make Datasets

You can make datasets as follows.

```
docker build --tag ffridataset-scripts .
docker run -v <path/to/here>/testbin:/work/testbin ffridataset-scripts test_main.py
# Note that data directory contains a CSV file and executable files which you want to process.
docker run -v <path/to/here>/data:/work/data -v <path/to/here>/out_dir:/work/out_dir ffridataset-scripts main.py --csv ./data/target.csv --out ./out_dir --log ./dataset.log --ver <version_string>
```

Please make sure that:

- The host directory that contains both a csv file and executable files is mounted to the container's `/work/data`.
- The host directory in which you want to output JSON files is mounted to the container's `/work/out_dir`.
- `<version_string>` should be vYYYY (e.g., `<version_string>` is v2021 for FFRI Dataset 2021).

## Run This Script Natively

### Prepare To Use

**Attention** We recommend that you run the following commands in the working directory (ffridataset-scripts directory).

```
sudo apt update

sudo apt install wget git gcc g++ make autoconf libfuzzy-dev unar cmake mlocate python3 python3-pip python3-dev libssl-dev python3-setuptools libglib2.0-0 libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential

poetry shell
poetry update --no-dev

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
cp triddefs_dir/triddefs-dataset2021.trd triddefs.trd

wget https://github.com/horsicq/DIE-engine/releases/download/3.01/die_lin64_portable_3.01.tar.gz
tar xzvf die_lin64_portable_3.01.tar.gz

git clone https://github.com/JusticeRage/Manalyze.git
cd Manalyze
git checkout 04cee36
cmake .
make
cd ../
```

### Run Tests

**Attention** Do not store a file named test.exe in the working directory. The test script copies testbin/test.exe in the directory and removes it.

```
python test_main.py
```

### Make Datasets

Before running this script, you need to make a CSV file described in [Make A CSV File](#Make-A-CSV-File) and specify this file path as an argument. Unlike using Docker, file paths can be specified as full paths.

**Attention** Do not store malware and cleanware in the working directory. This script copies malware and cleanware in the directory and removes them.

```
python main.py --csv <path/to/csv> --out <path/to/output_dataset_dir> --log <path/to/log_file> --ver <version_string>
```

## Notes About Hashes

- TLSH can be an empty string. This is because a file must have a sufficient amount of complexity to produce valid TLSH. See https://github.com/trendmicro/tlsh/blob/master/README.md for more details.
- peHashes (crits, endgame, and totalhash) can be null due to their implementation bugs.

## Notes About TrID Definition File

- TrID definition files included in [triddefs_dir](triddefs_dir) are redistributed with the permission from the TrID author, Marco Pontello.
- The latest definition file can be obtained from the [TrID website](https://mark0.net/soft-trid-e.html).

## Notes About LIEF

- This script uses the [patched version of LIEF](https://github.com/kohnakagawa/LIEF/tree/dev/ffridataset_2021).
- This LIEF is redistributed under [Apache-2.0 LICENSE](third-party-licenses/LIEF) as [whl file](dist_lief/lief-0.12.0.dev0-cp38-cp38-linux_x86_64.whl).

## Tested

- Ubuntu 20.04.2 LTS
- Ubuntu 20.04 on WSL2 on Windows 10 Pro 2004

## Development

### Profiling Measurement

First, you need to make the two folders.

```
mkdir out_dir
mkdir measurement
```

Next, build a docker image by specifying Dockerfile.measurement.

```
docker build --tag ffridataset-scripts . -f .\Dockerfile.measurement
```

Then, run the following command to make executables and a csv file.

```
docker run -v <path/to/here>\testbin:/work/testbin -v <path/to/here>\measurement\:/work/measurement ffridataset-scripts poetry run python create_measurement_env.py
```

Now you're ready to do profiling. To generate a cProfile result file, run

```
docker run -v <path/to/here>\measurement:/work/data -v <path/to/here>\out_dir:/work/out_dir ffridataset-scripts poetry run python -m cProfile -o ./out_dir/profiling.stats main.py --csv ./data/test.csv --out ./out_dir --log ./test.log --ver v2021
```

Then type

```
docker run -v <path/to/here>\out_dir\:/work/out_dir/ --rm -p 8080:8080 ffridataset-scripts poetry run snakeviz /work/out_dir/profiling.stats  -s -p 8080 -H 0.0.0.0
```

and you can see the profiling result through your browser.

## Author

Yuki Mogi. &copy; FFRI, Inc. 2019

Koh M. Nakagawa. &copy; FFRI, Inc. 2019
