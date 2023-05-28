FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev libssl-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y cmake

COPY . /repo
WORKDIR /repo/build
RUN cmake ..  -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install
ENV LD_LIBRARY_PATH=/install/lib

RUN clang++ /repo/mayhem/fuzz_resolve_domain.cpp /install/lib/libtins.so -fsanitize=fuzzer,address -I /repo/include/ -o /fuzz

FROM ubuntu:22.04 as package

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev libssl-dev

COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_resolve_domain
ENV LD_LIBRARY_PATH=/install/lib

