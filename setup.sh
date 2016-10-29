#! /bin/bash
echo "******************************************************"
echo "**** Installing                                   ****"
echo "****           _____         ____         _____   ****"	
echo "****  \    /  |     | |     |   _  |    |   |     ****"
echo "****   \  /   |     | |     |    | |    |   |     ****"
echo "****    \/    |_____| |____ |____| |____| __|__   ****"
echo "****                                              ****"
echo "******************************************************"

echo "update and upgrade..."
sudo apt-get update && sudo apt-get upgrade

echo "Installing python-dev, python-pip and git..."
sudo apt-get install python-dev python-pip git

echo "Installing django 1.9.6..."
sudo pip install Django==1.9.6

echo "Installing, distorm3, pymongo and pycrypto..."
sudo pip install distorm3 pymongo pycrypto

echo "Installing mongodb..."
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927
echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list
sudo apt-get update
sudo apt-get install -y mongodb-org
sudo apt-get install -y mongodb-org=3.2.6 mongodb-org-server=3.2.6 mongodb-org-shell=3.2.6 mongodb-org-mongos=3.2.6 mongodb-org-tools=3.2.6
echo "mongodb-org hold" | sudo dpkg --set-selections
echo "mongodb-org-server hold" | sudo dpkg --set-selections
echo "mongodb-org-shell hold" | sudo dpkg --set-selections
echo "mongodb-org-mongos hold" | sudo dpkg --set-selections
echo "mongodb-org-tools hold" | sudo dpkg --set-selections

echo "Installing volatility 2.5 or later..."
cd ~/
git clone https://github.com/volatilityfoundation/volatility
cd volatility
sudo python setup.py install

echo "Installing Yara..."
sudo apt-get install automake libtool
wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
tar zxf v3.4.0.tar.gz
cd yara-3.4.0
./bootstrap.sh
./configure
make
sudo make install
cd yara-python
sudo python setup.py install
sudo ldconfig

echo "Installing VirusTotal..."
sudo pip install virustotal



