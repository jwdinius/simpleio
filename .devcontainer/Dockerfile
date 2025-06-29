FROM ubuntu:22.04

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive
ARG USERNAME=simpleio

# Set up kitware apt repository
RUN apt-get update && apt-get install -y \
   ca-certificates \
   gnupg2 \
   wget
RUN rm -f /usr/share/keyrings/kitware-archive-keyring.gpg
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor -o /usr/share/keyrings/kitware-archive-keyring.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ jammy main" | tee /etc/apt/sources.list.d/kitware.list > /dev/null

RUN apt-get update && apt-get install -y \
   clang-format \
   clang-tidy \
   cppcheck \
   curl \
   python3 \
   python3-pip \
   git \
   sudo \
   build-essential \
   kitware-archive-keyring \
   cmake \
   libboost-all-dev \
   libpoco-dev \
   libgtest-dev \
   llvm \
   nlohmann-json3-dev \
   uncrustify \
   vim

RUN python3 -m pip install pre-commit cpplint

# setup user env at the end
# -m option creates a fake writable home folder
RUN adduser --disabled-password --gecos '' $USERNAME
RUN adduser $USERNAME sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $USERNAME
WORKDIR /home/$USERNAME
