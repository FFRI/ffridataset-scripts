# FFRI Dataset scripts

You can make datasets in the form of the FFRI dataset using this script.

## Requirements

We recommend that you use Docker for making datasets. See [Using Docker](#Using-Docker) for more details.

Alternatively, you can use this script by installing the following dependencies on [tested platforms](#Tested).
See [Run this script natively](#Run-This-Script-Natively) for more details.

- Python 3.9
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
docker build --target production --tag ffridataset-scripts .
docker run -v <path/to/here>/testbin:/work/testbin ffridataset-scripts test_main.py
# Note that data directory contains a CSV file and executable files which you want to process.
docker run -v <path/to/here>/data:/work/data -v <path/to/here>/out_dir:/work/out_dir ffridataset-scripts main.py --csv ./data/target.csv --out ./out_dir --log ./dataset.log --ver <version_string>
```

Please make sure that:

- The host directory that contains both a csv file and executable files is mounted to the container's `/work/data`.
- The host directory in which you want to output JSON files is mounted to the container's `/work/out_dir`.
- `<version_string>` should be vYYYY (e.g., `<version_string>` is v2022 for FFRI Dataset 2022).

To enable non-PE files to be processed, use `--not-pe-only` flag.

```
docker run -v <path/to/here>/data:/work/data -v <path/to/here>/out_dir:/work/out_dir ffridataset-scripts main.py --csv ./data/target.csv --out ./out_dir --log ./dataset.log --ver <version_string> --not-pe-only
```

If you want to use the script that produced the FFRI Dataset 2022, build `dataset` image as follows.

```
docker build --target dataset --tag ffridataset-scripts .
docker run -v <path/to/here>/testbin:/work/testbin ffridataset-scripts test_main.py
# Note that data directory contains a CSV file and executable files which you want to process.
docker run -v <path/to/here>/data:/work/data -v <path/to/here>/out_dir:/work/out_dir ffridataset-scripts main.py --csv ./data/target.csv --out ./out_dir --log ./dataset.log --ver <version_string>
```

## Run This Script Natively

### Prepare To Use

**Attention** We recommend that you run the following commands in the working directory (ffridataset-scripts directory).

```
sudo apt update

sudo apt install --no-install-recommends wget git gcc g++ make autoconf libfuzzy-dev unar cmake mlocate python3.9 python3-pip python3.9-dev libssl-dev python3-setuptools libglib2.0-0 curl libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential libpcre2-dev libdouble-conversion-dev

poetry shell
poetry install --no-dev

wget mark0.net/download/trid_linux_64.zip
unar trid_linux_64.zip
cp trid_linux_64/trid ./
chmod u+x trid
cp triddefs_dir/triddefs-dataset2022.trd triddefs.trd

cp die/die_3.05_portable_Ubuntu_20.04_amd64.tar.gz ./
tar xzf die_3.05_portable_Ubuntu_20.04_amd64.tar.gz

git clone https://github.com/JusticeRage/Manalyze.git
cd Manalyze
git checkout 639735735ef9a3753def23d2baee0d1e55a7c828
cmake .
make
cd ../
```

If something is wrong, see Dockerfile.

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

## Notes About DIE

- We use the modified version of DIE that we fixed [an issue](https://github.com/horsicq/Detect-It-Easy/issues/117), which we provide in the `die` directory.
- See the original DIE License file in the `third-party-licenses` directory.

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
docker build --target measurement --tag ffridataset-scripts .
```

Then, run the following command to make executables and a csv file.

```
docker run -v <path/to/here>\testbin:/work/testbin -v <path/to/here>\measurement\:/work/measurement ffridataset-scripts poetry run python create_measurement_env.py
```

Now you're ready to do profiling. To generate a cProfile result file, run

```
docker run -v <path/to/here>\measurement:/work/data -v <path/to/here>\out_dir:/work/out_dir ffridataset-scripts poetry run python -m cProfile -o ./out_dir/profiling.stats main.py --csv ./data/test.csv --out ./out_dir --log ./test.log --ver v2022
```

Then type

```
docker run -v <path/to/here>\out_dir\:/work/out_dir/ --rm -p 8080:8080 ffridataset-scripts poetry run snakeviz /work/out_dir/profiling.stats  -s -p 8080 -H 0.0.0.0
```

and you can see the profiling result through your browser.

## Author

Yuki Mogi. &copy; FFRI, Inc. 2019-2022

Koh M. Nakagawa. &copy; FFRI, Inc. 2019-2022
