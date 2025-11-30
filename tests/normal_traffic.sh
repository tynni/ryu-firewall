#!/bin/bash

echo "[*] Starting NORMAL traffic simulation..."


#Loop 15 times to simulate repeated user requests
for i in {1..15}
do
    ping -c 1 10.0.0.2 > /dev/null & #send 1 ping packet to host h2
    ping -c 1 10.0.0.3 > /dev/null & #send 1 ping packet to host h3
    sleep 1 #wait 1 second to avoid triggering the firewall
done

echo "[✓] Normal traffic finished."
