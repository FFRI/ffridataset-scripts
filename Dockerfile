FROM ubuntu:24.04 as base

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt update && \
    apt install -y --no-install-recommends wget git gcc g++ make autoconf libfuzzy-dev unar cmake plocate libssl-dev libglib2.0-0 curl libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential libpcre2-dev libdouble-conversion-dev && \
    apt install -y --no-install-recommends libqt5core5a libqt5svg5 libqt5gui5 libqt5widgets5 libqt5opengl5 libqt5dbus5 libqt5scripttools5 libqt5script5 libqt5network5 libqt5sql5 && \
    apt install -y --no-install-recommends libffi-dev libncurses5-dev zlib1g zlib1g-dev libreadline-dev libbz2-dev libsqlite3-dev liblzma-dev && \
    apt install -y --no-install-recommends software-properties-common gpg-agent gpg clang

VOLUME /work/data
VOLUME /work/out_dir
VOLUME /work/testbin

WORKDIR /work
RUN mkdir workspace

COPY triddefs_dir/triddefs-dataset2026.trd /work/triddefs.trd
COPY poetry.lock /work
COPY pyproject.toml /work
COPY workspace/pypeid-0.1.3-py3-none-any.whl /work/workspace

RUN wget https://github.com/horsicq/DIE-engine/releases/download/3.10/die_3.10_Ubuntu_24.04_amd64.deb && \
    apt --fix-broken install ./die_3.10_Ubuntu_24.04_amd64.deb && \
    rm die_3.10_Ubuntu_24.04_amd64.deb

RUN cd /work/workspace && \
    git clone https://github.com/JPCERTCC/impfuzzy.git && \
    cd impfuzzy && \
    git checkout b30548d005c9d980b3e3630648b39830597293fc

RUN cd /work/workspace && \
    git clone https://github.com/JusticeRage/Manalyze.git && \
    cd Manalyze && \
    git checkout 41ba9c57a40539bcb815ee03821c35ca66fff9be && \
    mkdir -p external && \
    cd external && \
    git clone https://github.com/JusticeRage/hash-library.git && \
    cd hash-library && \
    git checkout 5ecc248c68c30de02697105f3883938b1d476fed && \
    cd ../ && \
    git clone https://github.com/JusticeRage/yara.git && \
    cd yara && \
    git checkout aa06d68821ed8e6329c62ee5a865d63b211ac5ee && \
    cd ../../ && \
    cmake . -DGitHub=OFF && \
    make

RUN cd /work/workspace && \
    git clone https://github.com/lief-project/LIEF.git && \
    cd LIEF && \
    git checkout 6f3594f27056b85df51d6ad1c4ca944840ad3612

RUN cd /work/workspace && \
    git clone  https://github.com/trendmicro/tlsh.git && \
    cd tlsh && \
    git checkout 188c9c87158bda183cee2199f94236e4551018bd && \
    ./make.sh

RUN cd /work/workspace && \
    git clone https://github.com/erocarrera/pefile.git && \
    cd pefile && \
    git checkout 894605cc0d83146c6e1f481313979407df53e62e

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

ENV MISE_PYTHON_GITHUB_ATTESTATIONS=false

RUN mise install python@3.12.2 && \
    mise use -g python@3.12.2 && \
    python -m pip install --upgrade pip && \
    python -m pip install "poetry==1.8.3" && \
    python -m pip install --upgrade "cmake>=3.24"

ENV PATH /root/.local/share/mise/installs/python/3.12.2/bin:$PATH
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
