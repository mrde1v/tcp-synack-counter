# TCP SYN-ACK COUNTER
Counting TCP-SYN and TCP-ACK packets per second and overall + threshold control

# Install
Clone the repo
```
git clone https://github.com/mrde1v/tcp-synack-counter
```

Install scapy via pip
```
pip install scapy
```

# Run
default run with threshold 10
```
python3 packetmonitor.py <network-interface>
```

run with specified threshold
```
python3 packetmonitor.py <network-interface> --threshold <number>
```

# Explanation of files

## overall.txt
save IP + SYN and ACK packets overall time it was running

## persecond.txt
save IP + SYN and ACK packets per second

## ips.txt
save IP + packet hit number only if the threshold was exceeded


### made by de1v <3