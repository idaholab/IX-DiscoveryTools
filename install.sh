#!/bin/bash
#Copyright 2021, Battelle Energy Alliance, LLC
sudo apt update
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install tshark
if ! groups | grep wireshark > /dev/null; then
  sudo usermod -aG wireshark $USER
fi
sudo apt install git python3-venv python3-pip nmap  git-lfs -y

read -p "Do you want to install docker (y/N)?" yn
if [ "$yn" != "${yn#[Yy]}" ] ;then
  ./docker-install.sh
fi

python3 -m pip install poetry
PATH=$PATH:$HOME/.local/bin
poetry install
echo "You should reboot now, then use poetry shell"
