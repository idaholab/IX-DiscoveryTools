sudo apt update
sudo apt install python3-venv python3-pip nmap tshark -y
python3 -m pip install poetry
PATH=$PATH:$HOME/.local/bin
poetry install
echo "You should reboot now, then use poetry shell"
