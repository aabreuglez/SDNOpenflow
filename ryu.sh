#!/bin/bash
apt-get install -y libpython2.7-dev
#(apt-get remove python-six)
sleep 2
apt-get update
sleep 3
apt-get install -y python-pip
sleep 5
pip install ryu
sleep 5
pip install --upgrade six
