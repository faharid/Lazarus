FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends outguess ssss gnupg coreutils && rm -rf /var/lib/apt/lists/*
COPY crear.sh recuperar.sh /kit/
RUN chmod +x /kit/*.sh
WORKDIR /datos
