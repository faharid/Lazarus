FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends outguess ssss gnupg coreutils python3 && rm -rf /var/lib/apt/lists/*
COPY crear.sh recuperar.sh palabras.py palabras-es.txt palabras-evitar.txt /kit/
RUN chmod +x /kit/*.sh
WORKDIR /datos
