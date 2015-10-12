#!/bin/bash
set -e

make -j4
./avrdude -C avrdude.conf -J > parts.js
node parts.js
cat parts.js | python compress.py > parts.min.js
node parts.min.js
wc parts.min.js
