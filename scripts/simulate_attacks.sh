#!/usr/bin/env bash
# Microsoft Sentinel Attack Simulations

echo "[*] Simulating SSH Brute-Force..."
for i in {1..10}; do ssh invalid_user@localhost -o NumberOfPasswordPrompts=1; done

echo "[*] Simulating Unauthorized Sudo Attempt..."
sudo -u nobody sudo -l
