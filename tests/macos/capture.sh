#!/bin/sh
# Save raw output of the macOS tools the monitor parses, to compare with
# tests/macos/fixtures (CI uploads it as an artifact). Run on a Mac:
#   tests/macos/capture.sh [out-dir]
# The output contains this machine's addresses and app names: review it
# before sharing.
out=${1:-macos-capture}; mkdir -p "$out"
python3 -c "import socket,time; s=socket.create_connection(('1.1.1.1',443)); time.sleep(8)" &
sleep 2
lsof -nP -w -i -T s -F pcuPnT > "$out/lsof.txt" 2>&1
nettop -L 1 -n -x -J bytes_in,bytes_out > "$out/nettop.txt" 2>&1
ps -axww -o pid=,ppid=,uid=,lstart=,comm= > "$out/ps.txt" 2>&1
netstat -ibn > "$out/netstat.txt" 2>&1
networksetup -listallhardwareports > "$out/hardwareports.txt" 2>&1
for dev in $(networksetup -listallhardwareports | awk '/^Device:/{print $2}'); do
  ipconfig getsummary "$dev" > "$out/ipconfig-$dev.txt" 2>&1
done
codesign -dv --verbose=2 /usr/bin/curl > "$out/codesign-curl.txt" 2>&1
codesign -dv --verbose=2 /System/Applications/Calculator.app > "$out/codesign-calculator.txt" 2>&1
spctl -a -t exec -vv /System/Applications/Calculator.app > "$out/spctl-calculator.txt" 2>&1
sw_vers > "$out/sw_vers.txt"; uname -m >> "$out/sw_vers.txt"
wait
echo "saved to $out"
