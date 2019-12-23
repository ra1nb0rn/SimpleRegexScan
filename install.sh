#!/bin/bash

which pip3 &> /dev/null
if [ $? -eq 0 ]; then
    pip3 install -r requirements.txt
else
    pip install -r requirements.txt
fi

ln -sf "$(pwd)/simple_regex_scan.py" /usr/local/bin/simple_regex_scan
