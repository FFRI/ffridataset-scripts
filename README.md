# FFRI Dataset scripts

This script allows you to create datasets in the same format as the FFRI dataset.

## Requirements

We recommend using Docker to create datasets. For more information, refer to the [Using Docker](#Using-Docker) section.

Alternatively, you can run this script natively by installing the following dependencies on [tested platforms](#Tested). For detailed instructions, see the [Run this script natively](#Run-This-Script-Natively) section.

- Python 3.12
- [Poetry](https://python-poetry.org/) 1.7+

## Using Docker

### Make A CSV File

This script requires a CSV file that contains file information such as labels, dates, and file paths. For example:

```
path,label,date
./data/cleanware/test0.exe,0,2018/01/01
./data/malware/test1.exe,1,2018/01/02
```

Please note that the file paths in the CSV file should be specified as relative paths from the container's working directory.

### Make Datasets

You can create datasets using the following commands:

```
docker build --target production --tag ffridataset-scripts .
docker run -v <path/to/here>/testbin:/work/testbin ffridataset-scripts test_main.py
# Note: The data directory should contain a CSV file and the executable files you want to process.
docker run -v <path/to/here>/data:/work/data -v <path/to/here>/out_dir:/work/out_dir ffridataset-scripts main.py --csv ./data/target.csv --out ./out_dir --log ./dataset.log --ver <version_string>
```

Please ensure the following:

- The host directory containing the CSV file and executable files is mounted to the container’s `/work/data`.
- The host directory where you want to save the JSON files is mounted to the container’s `/work/out_dir`.
- Replace `<version_string>` with vYYYY (e.g., use v2024 for the FFRI Dataset 2024).

To process non-PE files, include the --not-pe-only flag:
```
docker run -v <path/to/here>/data:/work/data -v <path/to/here>/out_dir:/work/out_dir ffridataset-scripts main.py --csv ./data/target.csv --out ./out_dir --log ./dataset.log --ver <version_string> --not-pe-only
```

## Run This Script Natively

### Prepare To Use

**Attention** We recommend running the following commands in the working directory (the ffridataset-scripts directory).
```
export LC_ALL=C.UTF-8
export LANG=C.UTF-8

sudo apt update
sudo apt install -y --no-install-recommends wget git gcc g++ make autoconf libfuzzy-dev unar cmake mlocate libssl-dev libglib2.0-0 curl libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential libpcre2-dev libdouble-conversion-dev
sudo apt install -y --no-install-recommends libqt5core5a libqt5svg5 libqt5gui5 libqt5widgets5 libqt5opengl5 libqt5dbus5 libqt5scripttools5 libqt5script5 libqt5network5 libqt5sql5
sudo apt install -y --no-install-recommends libffi-dev libncurses5-dev zlib1g zlib1g-dev libreadline-dev libbz2-dev libsqlite3-dev liblzma-dev
sudo apt install -y --no-install-recommends software-properties-common gpg-agent gpg clang
wget https://github.com/horsicq/DIE-engine/releases/download/3.09/die_3.09_Ubuntu_22.04_amd64.deb
sudo apt --fix-broken install ./die_3.09_Ubuntu_22.04_amd64.deb
rm die_3.09_Ubuntu_22.04_amd64.deb

wget mark0.net/download/trid_linux_64.zip
unar trid_linux_64.zip
cp trid_linux_64/trid ./
chmod u+x trid
cp triddefs_dir/triddefs-dataset2024.trd triddefs.trd

cd workspace

git clone https://github.com/JPCERTCC/impfuzzy.git
cd impfuzzy
git checkout b30548d005c9d980b3e3630648b39830597293fc
cd ../

git clone https://github.com/JusticeRage/Manalyze.git
cd Manalyze
git checkout b6800ffcf2f7f4e82fe1f94d0eb2736e75e175ec
cmake .
make
cd ../

git clone https://github.com/lief-project/LIEF.git
cd LIEF
git checkout 573c885de5a2bb217d4d0255b54f9b53d9a4d7c9
git apply ../../patches/lief.patch
cd ../

git clone  https://github.com/trendmicro/tlsh.git
cd tlsh
git checkout 96536e3f5b9b322b44ce88d36126121685e45a77
./make.sh
cd ../

git clone https://github.com/erocarrera/pefile.git
cd pefile
git checkout ceab92e003b3436d2e52b74e9c903e812a4aeae1
cd ../../

wget https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-linux.zip
unar ninja-linux.zip
sudo mv ninja /usr/bin/

poetry install --no-root
```

If something goes wrong, refer to the Dockerfile.

### Run Tests

**Attention** Do not store a file named `test.exe` in the working directory. The test script copies `testbin/test.exe` into the directory and then removes it.
```
poetry run python test_main.py
```

### Make Datasets

Before running this script, you need to make a CSV file described in the [Make A CSV File](#Make-A-CSV-File) section and specify its file path as an argument. Unlike when using Docker, file paths can be specified as full paths.

**Attention** Do not store malware and cleanware in the working directory. This script will copy malware and cleanware into the directory and then removes them.

```
poetry run python main.py --csv <path/to/csv> --out <path/to/output_dataset_dir> --log <path/to/log_file> --ver <version_string>
```

## Notes About Hashes

- TLSH may sometimes be an empty string. This occurs because a file must possess a sufficient level of complexity to generate a valid TLSH. For more details, visit https://github.com/trendmicro/tlsh/blob/master/README.md.
- The peHashes (crits, endgame, and totalhash) can be null due to bugs in their implementation.

## Notes About TrID Definition File

- The TrID definition files located in [triddefs_dir](triddefs_dir) are redistributed with the permission from the TrID author, Marco Pontello.
- The latest definition file can be obtained from the [TrID website](https://mark0.net/soft-trid-e.html).

## Tested

- Ubuntu 22.04.2 LTS
- Ubuntu 22.04 on WSL2 on Windows 10

## Development

### Profiling Measurement

First, create two folders:
```
mkdir out_dir
mkdir measurement
```

Next, build a Docker image by specifying the measurement target:
```
docker build --target measurement --tag ffridataset-scripts .
```

Then, run the following command to generate executables and a csv file:
```
docker run -v <path/to/here>\testbin:/work/testbin -v <path/to/here>\measurement\:/work/measurement ffridataset-scripts poetry run python create_measurement_env.py
```

Now you're ready to do profiling. To generate a cProfile result file, run:
```
docker run -v <path/to/here>\measurement:/work/data -v <path/to/here>\out_dir:/work/out_dir ffridataset-scripts poetry run python -m cProfile -o ./out_dir/profiling.stats main.py --csv ./data/test.csv --out ./out_dir --log ./test.log --ver v2023
```

Then, execute the following command:
```
docker run -v <path/to/here>\out_dir\:/work/out_dir/ --rm -p 8080:8080 ffridataset-scripts poetry run snakeviz /work/out_dir/profiling.stats  -s -p 8080 -H 0.0.0.0
```

Now, you can view the profiling results through your browser.

## Author

Yuki Mogi. &copy; FFRI, Inc. 2019-2024

Koh M. Nakagawa. &copy; FFRI, Inc. 2019-2024
