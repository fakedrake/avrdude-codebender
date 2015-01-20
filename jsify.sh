make && ./avrdude -p \? -C avrdude.conf -v |& awk 'BEGIN {p = 0} /BEGIN PARTS/{p=1} (p>0) {print}' > parts.js && node parts.js
