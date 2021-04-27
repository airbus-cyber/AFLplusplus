#!/bin/sh

rm -Rf afl_ghidra_emu 2>/dev/null
git clone https://github.com/airbus-cyber/afl_ghidra_emu

test -d afl_ghidra_emu || { echo "[-] not checked out, please install git or check your internet connection." ; exit 1 ; }

echo "[+] Got unicornafl."

echo "================================================="
echo "/!\ Copy content of afl_ghidra_emu directory to"
echo "    your ghidra script directory"
echo "(Ex: cp -r afl_ghidra_emu/* $USER_HOME/ghidra_scripts/)"
echo "================================================="




