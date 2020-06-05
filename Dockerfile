FROM ubuntu:18.04

VOLUME /work/data
VOLUME /work/out_dir
VOLUME /work/testbin

WORKDIR /work

COPY main.py /work
COPY test_main.py /work
COPY triddefs_dir/triddefs-dataset2020.trd /work/triddefs.trd
COPY Pipfile /work
COPY Pipfile.lock /work
COPY dist_lief/lief-0.11.0.ffridataset2020-cp36-none-linux_x86_64.whl /work

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt update && \
    apt install -y --no-install-recommends wget git gcc g++ make autoconf libfuzzy-dev unar cmake mlocate python3 python3-pip python3-dev libssl1.0.0 libssl-dev python3-setuptools && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install wheel&& \
    pip3 install pipenv&& \
    pipenv sync && \
    pipenv run pip install lief-0.11.0.ffridataset2020-cp36-none-linux_x86_64.whl

RUN git clone https://github.com/trendmicro/tlsh.git && \
    cd tlsh && \
    git checkout 4.2.1 && \
    ./make.sh && \
    cd py_ext && \
    pipenv run python ./setup.py install && \
    cd ../../ && \
    rm -rf tlsh

RUN wget mark0.net/download/trid_linux_64.zip && \
    unar trid_linux_64.zip && \
    cp trid_linux_64/trid ./ && \
    chmod u+x trid && \
    rm -rf trid_linux64 trid_linux64.zip

ENTRYPOINT ["pipenv", "run", "python"]

