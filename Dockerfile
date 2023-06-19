FROM ubuntu:22.04 as base

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt update && \
    apt install -y --no-install-recommends wget git gcc g++ make autoconf libfuzzy-dev unar cmake mlocate python3.11 python3-pip python3.11-dev libssl-dev python3-setuptools libglib2.0-0 curl libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential libpcre2-dev libdouble-conversion-dev && \
    apt install -y --no-install-recommends libqt5core5a libqt5svg5 libqt5gui5 libqt5widgets5 libqt5opengl5 libqt5dbus5 libqt5scripttools5 libqt5script5 libqt5network5 libqt5sql5 && \
    rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 100 && \
    python3 -v

VOLUME /work/data
VOLUME /work/out_dir
VOLUME /work/testbin

WORKDIR /work
RUN mkdir workspace

COPY triddefs_dir/triddefs-dataset2023.trd /work/triddefs.trd
COPY docker/poetry.lock /work
COPY docker/pyproject.toml /work
COPY workspace/pypeid-0.1.2-py3-none-any.whl /work/workspace

RUN wget https://github.com/horsicq/DIE-engine/releases/download/3.07/die_3.07_Ubuntu_22.04_amd64.deb && \
    apt --fix-broken install ./die_3.07_Ubuntu_22.04_amd64.deb && \
    rm die_3.07_Ubuntu_22.04_amd64.deb

RUN cd /work/workspace && \
    git clone https://github.com/JPCERTCC/impfuzzy.git && \
    cd impfuzzy && \
    git checkout b30548d005c9d980b3e3630648b39830597293fc && \
    cd ../..

RUN wget mark0.net/download/trid_linux_64.zip && \
    unar trid_linux_64.zip && \
    cp trid_linux_64/trid ./ && \
    chmod u+x trid && \
    rm -rf trid_linux64 trid_linux64.zip

RUN git clone https://github.com/JusticeRage/Manalyze.git && \
    cd Manalyze && \
    git checkout e951f343e092350d8380149faea3aa543cf5fae8 && \
    cmake . && \
    make && \
    cd ../

ENV PATH /root/.poetry/bin:$PATH

RUN pip3 install wheel && \
    curl -sSL https://install.python-poetry.org | python3.11 -


ENV PATH /root/.local/bin:$PATH

RUN poetry config installer.max-workers 10

RUN poetry install -vvv --no-root

RUN poetry run pip install workspace/pypeid-0.1.2-py3-none-any.whl

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
