FROM ubuntu:22.04 as base

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt update && \
    apt install -y --no-install-recommends wget git gcc g++ make autoconf libfuzzy-dev unar cmake mlocate libssl-dev libglib2.0-0 curl libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential libpcre2-dev libdouble-conversion-dev && \
    apt install -y --no-install-recommends libqt5core5a libqt5svg5 libqt5gui5 libqt5widgets5 libqt5opengl5 libqt5dbus5 libqt5scripttools5 libqt5script5 libqt5network5 libqt5sql5 && \
    apt install -y --no-install-recommends libffi-dev libncurses5-dev zlib1g zlib1g-dev libreadline-dev libbz2-dev libsqlite3-dev liblzma-dev && \
    apt install -y --no-install-recommends software-properties-common gpg-agent gpg clang

VOLUME /work/data
VOLUME /work/out_dir
VOLUME /work/testbin

WORKDIR /work
RUN mkdir workspace

COPY triddefs_dir/triddefs-dataset2024.trd /work/triddefs.trd
COPY poetry.lock /work
COPY pyproject.toml /work
COPY workspace/pypeid-0.1.3-py3-none-any.whl /work/workspace
COPY patches/lief.patch /work

RUN wget https://github.com/horsicq/DIE-engine/releases/download/3.09/die_3.09_Ubuntu_22.04_amd64.deb && \
    apt --fix-broken install ./die_3.09_Ubuntu_22.04_amd64.deb && \
    rm die_3.09_Ubuntu_22.04_amd64.deb

RUN cd /work/workspace && \
    git clone https://github.com/JPCERTCC/impfuzzy.git && \
    cd impfuzzy && \
    git checkout b30548d005c9d980b3e3630648b39830597293fc

RUN cd /work/workspace && \
    git clone https://github.com/JusticeRage/Manalyze.git && \
    cd Manalyze && \
    git checkout b6800ffcf2f7f4e82fe1f94d0eb2736e75e175ec && \
    cmake . && \
    make

RUN cd /work/workspace && \
    git clone https://github.com/lief-project/LIEF.git && \
    cd LIEF && \
    git checkout 573c885de5a2bb217d4d0255b54f9b53d9a4d7c9 && \
    git apply /work/lief.patch

RUN cd /work/workspace && \
    git clone  https://github.com/trendmicro/tlsh.git && \
    cd tlsh && \
    git checkout 96536e3f5b9b322b44ce88d36126121685e45a77 && \
    ./make.sh

RUN cd /work/workspace && \
    git clone https://github.com/erocarrera/pefile.git && \
    cd pefile && \
    git checkout ceab92e003b3436d2e52b74e9c903e812a4aeae1

RUN wget mark0.net/download/trid_linux_64.zip && \
    unar trid_linux_64.zip && \
    cp trid_linux_64/trid ./ && \
    chmod u+x trid && \
    rm -rf trid_linux64 trid_linux64.zip

RUN install -dm 755 /etc/apt/keyrings && \
    wget -qO - https://mise.jdx.dev/gpg-key.pub | gpg --dearmor | tee /etc/apt/keyrings/mise-archive-keyring.gpg 1> /dev/null && \
    echo "deb [signed-by=/etc/apt/keyrings/mise-archive-keyring.gpg arch=amd64] https://mise.jdx.dev/deb stable main" | tee /etc/apt/sources.list.d/mise.list && \
    apt update && \
    apt install -y mise && \
    echo 'eval "$(/usr/bin/mise activate bash)"' >> ~/.bashrc

ENV PATH /root/.local/share/mise/shims:$PATH

RUN mise install python@3.12.2 && \
    mise use -g python@3.12.2 && \
    mise plugin add poetry && \
    mise install poetry 1.8.3 && \
    mise use -g poetry@1.8.3

ENV PATH /root/.local/bin:$PATH
                
RUN poetry config installer.max-workers 10      

RUN wget https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-linux.zip && \
    unar ninja-linux.zip && \
    mv ninja /usr/bin/

RUN poetry install -vvv --no-root

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
