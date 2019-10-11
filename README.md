# ffridataset2019

You can make datasets like FFRI Dataset 2019 by using this script.

## Requirements

- Python 3.6
- pipenv

Alternatively, you can use Docker. See [Using Docker](#Using-Docker).

## Prepare To Use

**Attention** We recommend that you run the following commands in the working directory (ffridataset2019 directory).

```
sudo apt install libfuzzy-dev
sudo apt install unar
sudo apt install cmake

pipenv shell
pipenv install

git clone https://github.com/knowmalware/pehash.git
cd pehash
python setup.py install
cd ..

wget https://github.com/trendmicro/tlsh/archive/master.zip -O tlsh-master.zip
unar tlsh-master.zip
cd tlsh-master
./make.sh
cd py_ext
python ./setup.py install
cd ../Testing
./python_test.sh
cd ../..

wget mark0.net/download/trid_linux_64.zip
unar trid_linux_64.zip
cp trid_linux_64/trid ./
wget mark0.net/download/triddefs.zip
unar triddefs.zip

wget https://github.com/K-atc/PEiD/releases/download/v0.1.1/PEiD
./PEiD --prepare
sudo updatedb
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

**Attention** Do not store malware and cleanware in the working directory. Due to the limitation of trid, the script copies malware and cleanware in the directory and removes them.

```
python main.py --csv <path/to/csv> --out <path/to/output_dataset_dir> --log <path/to/log_file>
```

## Using Docker

```
docker build --tag ffridataset2019 .
docker run -v <path/to/here>/testbin:/work/testbin ffridataset2019 python3 test_main.py
# Note that data directory contains a CSV file and executable files which you want to process.
docker run -v <path/to/here>/data:/work/data -v <path/to/here>/out_dir:/work/out_dir ffridataset2019 python3 main.py --csv ./data/target.csv --out ./out_dir --log ./dataset.log
```

When using Docker, there exist some limitations:
- file paths in a CSV file should be specified as a relative path to the container's working directory. Example CSV file is as follows.

```
path,label,date
./data/cleanware/test0.exe,0,2018/01/01
./data/malware/test1.exe,1,2018/01/02
```

- You should mount the host directory which contains both a csv file and executable files to the container's `/work/data`.
- You should mount the host directory in which you want to output JSON files to the container's `/work/out_dir`.

## Notes about hashes

- tlsh can be an empty string. This is because a file must have a sufficient amount of complexity to produce valid tlsh. See https://github.com/trendmicro/tlsh/blob/master/README.md .
- pehashes can be null.

## TESTED

- Ubuntu 18.04 on WSL on Windows 10 Pro 1803

## Author

Yuki Mogi. &copy; FFRI, Inc. 2019

Koh M. Nakagawa. &copy; FFRI, Inc. 2019
