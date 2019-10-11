FROM ubuntu:18.04

VOLUME /work/data
VOLUME /work/out_dir
VOLUME /work/testbin

WORKDIR /work

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt install -y --no-install-recommends wget gcc g++ make autoconf libfuzzy-dev unar cmake mlocate python3 python3-pip python3-dev libssl1.0.0 libssl-dev python3-setuptools && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install ssdeep pyimpfuzzy lief pefile pandas yara-python numpy logzero

RUN wget https://github.com/knowmalware/pehash/archive/master.zip -O pehash-master.zip && \
    unar pehash-master.zip && \
    cd pehash-master && \
    python3 setup.py install && \
    cd ../ && \
    rm -rf pehash-master*

RUN wget https://github.com/trendmicro/tlsh/archive/master.zip -O tlsh-master.zip && \
    unar tlsh-master.zip && \
    cd tlsh-master && \
    ./make.sh && \
    cd py_ext && \
    python3 ./setup.py install && \
    cd ../../ && \
    rm -rf tlsh-master*

RUN wget mark0.net/download/trid_linux_64.zip && \
    unar trid_linux_64.zip && \
    cp trid_linux_64/trid ./ && \
    chmod u+x ./trid && \
    wget mark0.net/download/triddefs.zip && \
    unar triddefs.zip && \
    rm -rf trid_linux64 trid_linux64.zip triddefs.zip

RUN wget https://github.com/K-atc/PEiD/releases/download/v0.1.1/PEiD && \
    chmod u+x ./PEiD && \
    ./PEiD --prepare

RUN updatedb

COPY main.py /work
COPY test_main.py /work

