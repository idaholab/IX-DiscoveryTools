#!/bin/bash
#Copyright 2021, Battelle Energy Alliance, LLC
sudo apt update
if ! which docker; then
  wget https://get.docker.com -O get-docker.sh
  sudo sh get-docker.sh
fi
if ! getent group | grep docker > /dev/null; then
  sudo groupadd docker
fi
if ! groups | grep docker > /dev/null; then
  sudo usermod -aG docker $USER
fi
sudo apt install git python3-venv python3-pip nmap git-lfs -y
git lfs install
GIT_SSL_NO_VERIFY=true git lfs pull --exclude=""
sh -c "cd autodiscover/openvas && sudo ./import.sh && sudo ./run.sh && cd .."

