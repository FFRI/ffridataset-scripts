FROM ubuntu:20.04 as base

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt update && \
    apt install -y --no-install-recommends wget git gcc g++ make autoconf libfuzzy-dev unar cmake mlocate python3.9 python3-pip python3.9-dev libssl-dev python3-setuptools libglib2.0-0 curl libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential libpcre2-dev libdouble-conversion-dev && \
    rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 100&& \
    python3 -v

VOLUME /work/data
VOLUME /work/out_dir
VOLUME /work/testbin

WORKDIR /work
RUN mkdir workspace

COPY triddefs_dir/triddefs-dataset2022.trd /work/triddefs.trd
COPY poetry.lock /work
COPY pyproject.toml /work
COPY workspace/pypeid-0.1.0-py3-none-any.whl /work/workspace
COPY die/die_3.05_portable_Ubuntu_20.04_amd64.tar.gz /work

RUN tar xzf die_3.05_portable_Ubuntu_20.04_amd64.tar.gz && \
    rm die_3.05_portable_Ubuntu_20.04_amd64.tar.gz

RUN pip3 install wheel&& \
    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3.9&& \
    . /root/.poetry/env&&\
    poetry install

ENV PATH /root/.poetry/bin:$PATH

RUN wget mark0.net/download/trid_linux_64.zip && \
    unar trid_linux_64.zip && \
    cp trid_linux_64/trid ./ && \
    chmod u+x trid && \
    rm -rf trid_linux64 trid_linux64.zip

RUN git clone https://github.com/JusticeRage/Manalyze.git && \
    cd Manalyze && \
    git checkout 639735735ef9a3753def23d2baee0d1e55a7c828 && \
    cmake . && \
    make && \
    cd ../

FROM base as dataset

COPY dataset.py /work/main.py
COPY test_dataset.py /work/test_main.py
ENTRYPOINT ["poetry", "run", "python"]

FROM base as production

COPY main.py /work
COPY test_main.py /work
ENTRYPOINT ["poetry", "run", "python"]

FROM base as measurement

VOLUME /work/measurement
COPY main.py /work
COPY scripts/create_measurement_env.py /work

FROM base as test

COPY scripts/create_test_files.py /work
ENTRYPOINT ["poetry", "run", "python"]
