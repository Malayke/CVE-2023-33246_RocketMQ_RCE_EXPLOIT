import socket
import json
import sys
from concurrent.futures import ThreadPoolExecutor
import argparse
import requests
from urllib.parse import urlparse
import ipaddress

# from https://github.com/apache/rocketmq/blob/develop/common/src/main/java/org/apache/rocketmq/common/MQVersion.java
version_list = ["V3_0_0_SNAPSHOT","V3_0_0_ALPHA1","V3_0_0_BETA1","V3_0_0_BETA2","V3_0_0_BETA3","V3_0_0_BETA4","V3_0_0_BETA5","V3_0_0_BETA6_SNAPSHOT","V3_0_0_BETA6","V3_0_0_BETA7_SNAPSHOT","V3_0_0_BETA7","V3_0_0_BETA8_SNAPSHOT","V3_0_0_BETA8","V3_0_0_BETA9_SNAPSHOT","V3_0_0_BETA9","V3_0_0_FINAL","V3_0_1_SNAPSHOT","V3_0_1","V3_0_2_SNAPSHOT","V3_0_2","V3_0_3_SNAPSHOT","V3_0_3","V3_0_4_SNAPSHOT","V3_0_4","V3_0_5_SNAPSHOT","V3_0_5","V3_0_6_SNAPSHOT","V3_0_6","V3_0_7_SNAPSHOT","V3_0_7","V3_0_8_SNAPSHOT","V3_0_8","V3_0_9_SNAPSHOT","V3_0_9","V3_0_10_SNAPSHOT","V3_0_10","V3_0_11_SNAPSHOT","V3_0_11","V3_0_12_SNAPSHOT","V3_0_12","V3_0_13_SNAPSHOT","V3_0_13","V3_0_14_SNAPSHOT","V3_0_14","V3_0_15_SNAPSHOT","V3_0_15","V3_1_0_SNAPSHOT","V3_1_0","V3_1_1_SNAPSHOT","V3_1_1","V3_1_2_SNAPSHOT","V3_1_2","V3_1_3_SNAPSHOT","V3_1_3","V3_1_4_SNAPSHOT","V3_1_4","V3_1_5_SNAPSHOT","V3_1_5","V3_1_6_SNAPSHOT","V3_1_6","V3_1_7_SNAPSHOT","V3_1_7","V3_1_8_SNAPSHOT","V3_1_8","V3_1_9_SNAPSHOT","V3_1_9","V3_2_0_SNAPSHOT","V3_2_0","V3_2_1_SNAPSHOT","V3_2_1","V3_2_2_SNAPSHOT","V3_2_2","V3_2_3_SNAPSHOT","V3_2_3","V3_2_4_SNAPSHOT","V3_2_4","V3_2_5_SNAPSHOT","V3_2_5","V3_2_6_SNAPSHOT","V3_2_6","V3_2_7_SNAPSHOT","V3_2_7","V3_2_8_SNAPSHOT","V3_2_8","V3_2_9_SNAPSHOT","V3_2_9","V3_3_1_SNAPSHOT","V3_3_1","V3_3_2_SNAPSHOT","V3_3_2","V3_3_3_SNAPSHOT","V3_3_3","V3_3_4_SNAPSHOT","V3_3_4","V3_3_5_SNAPSHOT","V3_3_5","V3_3_6_SNAPSHOT","V3_3_6","V3_3_7_SNAPSHOT","V3_3_7","V3_3_8_SNAPSHOT","V3_3_8","V3_3_9_SNAPSHOT","V3_3_9","V3_4_1_SNAPSHOT","V3_4_1","V3_4_2_SNAPSHOT","V3_4_2","V3_4_3_SNAPSHOT","V3_4_3","V3_4_4_SNAPSHOT","V3_4_4","V3_4_5_SNAPSHOT","V3_4_5","V3_4_6_SNAPSHOT","V3_4_6","V3_4_7_SNAPSHOT","V3_4_7","V3_4_8_SNAPSHOT","V3_4_8","V3_4_9_SNAPSHOT","V3_4_9","V3_5_1_SNAPSHOT","V3_5_1","V3_5_2_SNAPSHOT","V3_5_2","V3_5_3_SNAPSHOT","V3_5_3","V3_5_4_SNAPSHOT","V3_5_4","V3_5_5_SNAPSHOT","V3_5_5","V3_5_6_SNAPSHOT","V3_5_6","V3_5_7_SNAPSHOT","V3_5_7","V3_5_8_SNAPSHOT","V3_5_8","V3_5_9_SNAPSHOT","V3_5_9","V3_6_1_SNAPSHOT","V3_6_1","V3_6_2_SNAPSHOT","V3_6_2","V3_6_3_SNAPSHOT","V3_6_3","V3_6_4_SNAPSHOT","V3_6_4","V3_6_5_SNAPSHOT","V3_6_5","V3_6_6_SNAPSHOT","V3_6_6","V3_6_7_SNAPSHOT","V3_6_7","V3_6_8_SNAPSHOT","V3_6_8","V3_6_9_SNAPSHOT","V3_6_9","V3_7_1_SNAPSHOT","V3_7_1","V3_7_2_SNAPSHOT","V3_7_2","V3_7_3_SNAPSHOT","V3_7_3","V3_7_4_SNAPSHOT","V3_7_4","V3_7_5_SNAPSHOT","V3_7_5","V3_7_6_SNAPSHOT","V3_7_6","V3_7_7_SNAPSHOT","V3_7_7","V3_7_8_SNAPSHOT","V3_7_8","V3_7_9_SNAPSHOT","V3_7_9","V3_8_1_SNAPSHOT","V3_8_1","V3_8_2_SNAPSHOT","V3_8_2","V3_8_3_SNAPSHOT","V3_8_3","V3_8_4_SNAPSHOT","V3_8_4","V3_8_5_SNAPSHOT","V3_8_5","V3_8_6_SNAPSHOT","V3_8_6","V3_8_7_SNAPSHOT","V3_8_7","V3_8_8_SNAPSHOT","V3_8_8","V3_8_9_SNAPSHOT","V3_8_9","V3_9_1_SNAPSHOT","V3_9_1","V3_9_2_SNAPSHOT","V3_9_2","V3_9_3_SNAPSHOT","V3_9_3","V3_9_4_SNAPSHOT","V3_9_4","V3_9_5_SNAPSHOT","V3_9_5","V3_9_6_SNAPSHOT","V3_9_6","V3_9_7_SNAPSHOT","V3_9_7","V3_9_8_SNAPSHOT","V3_9_8","V3_9_9_SNAPSHOT","V3_9_9","V4_0_0_SNAPSHOT","V4_0_0","V4_0_1_SNAPSHOT","V4_0_1","V4_0_2_SNAPSHOT","V4_0_2","V4_0_3_SNAPSHOT","V4_0_3","V4_0_4_SNAPSHOT","V4_0_4","V4_0_5_SNAPSHOT","V4_0_5","V4_0_6_SNAPSHOT","V4_0_6","V4_0_7_SNAPSHOT","V4_0_7","V4_0_8_SNAPSHOT","V4_0_8","V4_0_9_SNAPSHOT","V4_0_9","V4_1_0_SNAPSHOT","V4_1_0","V4_1_1_SNAPSHOT","V4_1_1","V4_1_2_SNAPSHOT","V4_1_2","V4_1_3_SNAPSHOT","V4_1_3","V4_1_4_SNAPSHOT","V4_1_4","V4_1_5_SNAPSHOT","V4_1_5","V4_1_6_SNAPSHOT","V4_1_6","V4_1_7_SNAPSHOT","V4_1_7","V4_1_8_SNAPSHOT","V4_1_8","V4_1_9_SNAPSHOT","V4_1_9","V4_2_0_SNAPSHOT","V4_2_0","V4_2_1_SNAPSHOT","V4_2_1","V4_2_2_SNAPSHOT","V4_2_2","V4_2_3_SNAPSHOT","V4_2_3","V4_2_4_SNAPSHOT","V4_2_4","V4_2_5_SNAPSHOT","V4_2_5","V4_2_6_SNAPSHOT","V4_2_6","V4_2_7_SNAPSHOT","V4_2_7","V4_2_8_SNAPSHOT","V4_2_8","V4_2_9_SNAPSHOT","V4_2_9","V4_3_0_SNAPSHOT","V4_3_0","V4_3_1_SNAPSHOT","V4_3_1","V4_3_2_SNAPSHOT","V4_3_2","V4_3_3_SNAPSHOT","V4_3_3","V4_3_4_SNAPSHOT","V4_3_4","V4_3_5_SNAPSHOT","V4_3_5","V4_3_6_SNAPSHOT","V4_3_6","V4_3_7_SNAPSHOT","V4_3_7","V4_3_8_SNAPSHOT","V4_3_8","V4_3_9_SNAPSHOT","V4_3_9","V4_4_0_SNAPSHOT","V4_4_0","V4_4_1_SNAPSHOT","V4_4_1","V4_4_2_SNAPSHOT","V4_4_2","V4_4_3_SNAPSHOT","V4_4_3","V4_4_4_SNAPSHOT","V4_4_4","V4_4_5_SNAPSHOT","V4_4_5","V4_4_6_SNAPSHOT","V4_4_6","V4_4_7_SNAPSHOT","V4_4_7","V4_4_8_SNAPSHOT","V4_4_8","V4_4_9_SNAPSHOT","V4_4_9","V4_5_0_SNAPSHOT","V4_5_0","V4_5_1_SNAPSHOT","V4_5_1","V4_5_2_SNAPSHOT","V4_5_2","V4_5_3_SNAPSHOT","V4_5_3","V4_5_4_SNAPSHOT","V4_5_4","V4_5_5_SNAPSHOT","V4_5_5","V4_5_6_SNAPSHOT","V4_5_6","V4_5_7_SNAPSHOT","V4_5_7","V4_5_8_SNAPSHOT","V4_5_8","V4_5_9_SNAPSHOT","V4_5_9","V4_6_0_SNAPSHOT","V4_6_0","V4_6_1_SNAPSHOT","V4_6_1","V4_6_2_SNAPSHOT","V4_6_2","V4_6_3_SNAPSHOT","V4_6_3","V4_6_4_SNAPSHOT","V4_6_4","V4_6_5_SNAPSHOT","V4_6_5","V4_6_6_SNAPSHOT","V4_6_6","V4_6_7_SNAPSHOT","V4_6_7","V4_6_8_SNAPSHOT","V4_6_8","V4_6_9_SNAPSHOT","V4_6_9","V4_7_0_SNAPSHOT","V4_7_0","V4_7_1_SNAPSHOT","V4_7_1","V4_7_2_SNAPSHOT","V4_7_2","V4_7_3_SNAPSHOT","V4_7_3","V4_7_4_SNAPSHOT","V4_7_4","V4_7_5_SNAPSHOT","V4_7_5","V4_7_6_SNAPSHOT","V4_7_6","V4_7_7_SNAPSHOT","V4_7_7","V4_7_8_SNAPSHOT","V4_7_8","V4_7_9_SNAPSHOT","V4_7_9","V4_8_0_SNAPSHOT","V4_8_0","V4_8_1_SNAPSHOT","V4_8_1","V4_8_2_SNAPSHOT","V4_8_2","V4_8_3_SNAPSHOT","V4_8_3","V4_8_4_SNAPSHOT","V4_8_4","V4_8_5_SNAPSHOT","V4_8_5","V4_8_6_SNAPSHOT","V4_8_6","V4_8_7_SNAPSHOT","V4_8_7","V4_8_8_SNAPSHOT","V4_8_8","V4_8_9_SNAPSHOT","V4_8_9","V4_9_0_SNAPSHOT","V4_9_0","V4_9_1_SNAPSHOT","V4_9_1","V4_9_2_SNAPSHOT","V4_9_2","V4_9_3_SNAPSHOT","V4_9_3","V4_9_4_SNAPSHOT","V4_9_4","V4_9_5_SNAPSHOT","V4_9_5","V4_9_6_SNAPSHOT","V4_9_6","V4_9_7_SNAPSHOT","V4_9_7","V4_9_8_SNAPSHOT","V4_9_8","V4_9_9_SNAPSHOT","V4_9_9","V5_0_0_SNAPSHOT","V5_0_0","V5_0_1_SNAPSHOT","V5_0_1","V5_0_2_SNAPSHOT","V5_0_2","V5_0_3_SNAPSHOT","V5_0_3","V5_0_4_SNAPSHOT","V5_0_4","V5_0_5_SNAPSHOT","V5_0_5","V5_0_6_SNAPSHOT","V5_0_6","V5_0_7_SNAPSHOT","V5_0_7","V5_0_8_SNAPSHOT","V5_0_8","V5_0_9_SNAPSHOT","V5_0_9","V5_1_0_SNAPSHOT","V5_1_0","V5_1_1_SNAPSHOT","V5_1_1","V5_1_2_SNAPSHOT","V5_1_2","V5_1_3_SNAPSHOT","V5_1_3","V5_1_4_SNAPSHOT","V5_1_4","V5_1_5_SNAPSHOT","V5_1_5","V5_1_6_SNAPSHOT","V5_1_6","V5_1_7_SNAPSHOT","V5_1_7","V5_1_8_SNAPSHOT","V5_1_8","V5_1_9_SNAPSHOT","V5_1_9","V5_2_0_SNAPSHOT","V5_2_0","V5_2_1_SNAPSHOT","V5_2_1","V5_2_2_SNAPSHOT","V5_2_2","V5_2_3_SNAPSHOT","V5_2_3","V5_2_4_SNAPSHOT","V5_2_4","V5_2_5_SNAPSHOT","V5_2_5","V5_2_6_SNAPSHOT","V5_2_6","V5_2_7_SNAPSHOT","V5_2_7","V5_2_8_SNAPSHOT","V5_2_8","V5_2_9_SNAPSHOT","V5_2_9","V5_3_0_SNAPSHOT","V5_3_0","V5_3_1_SNAPSHOT","V5_3_1","V5_3_2_SNAPSHOT","V5_3_2","V5_3_3_SNAPSHOT","V5_3_3","V5_3_4_SNAPSHOT","V5_3_4","V5_3_5_SNAPSHOT","V5_3_5","V5_3_6_SNAPSHOT","V5_3_6","V5_3_7_SNAPSHOT","V5_3_7","V5_3_8_SNAPSHOT","V5_3_8","V5_3_9_SNAPSHOT","V5_3_9","V5_4_0_SNAPSHOT","V5_4_0","V5_4_1_SNAPSHOT","V5_4_1","V5_4_2_SNAPSHOT","V5_4_2","V5_4_3_SNAPSHOT","V5_4_3","V5_4_4_SNAPSHOT","V5_4_4","V5_4_5_SNAPSHOT","V5_4_5","V5_4_6_SNAPSHOT","V5_4_6","V5_4_7_SNAPSHOT","V5_4_7","V5_4_8_SNAPSHOT","V5_4_8","V5_4_9_SNAPSHOT","V5_4_9","V5_5_0_SNAPSHOT","V5_5_0","V5_5_1_SNAPSHOT","V5_5_1","V5_5_2_SNAPSHOT","V5_5_2","V5_5_3_SNAPSHOT","V5_5_3","V5_5_4_SNAPSHOT","V5_5_4","V5_5_5_SNAPSHOT","V5_5_5","V5_5_6_SNAPSHOT","V5_5_6","V5_5_7_SNAPSHOT","V5_5_7","V5_5_8_SNAPSHOT","V5_5_8","V5_5_9_SNAPSHOT","V5_5_9","V5_6_0_SNAPSHOT","V5_6_0","V5_6_1_SNAPSHOT","V5_6_1","V5_6_2_SNAPSHOT","V5_6_2","V5_6_3_SNAPSHOT","V5_6_3","V5_6_4_SNAPSHOT","V5_6_4","V5_6_5_SNAPSHOT","V5_6_5","V5_6_6_SNAPSHOT","V5_6_6","V5_6_7_SNAPSHOT","V5_6_7","V5_6_8_SNAPSHOT","V5_6_8","V5_6_9_SNAPSHOT","V5_6_9","V5_7_0_SNAPSHOT","V5_7_0","V5_7_1_SNAPSHOT","V5_7_1","V5_7_2_SNAPSHOT","V5_7_2","V5_7_3_SNAPSHOT","V5_7_3","V5_7_4_SNAPSHOT","V5_7_4","V5_7_5_SNAPSHOT","V5_7_5","V5_7_6_SNAPSHOT","V5_7_6","V5_7_7_SNAPSHOT","V5_7_7","V5_7_8_SNAPSHOT","V5_7_8","V5_7_9_SNAPSHOT","V5_7_9","V5_8_0_SNAPSHOT","V5_8_0","V5_8_1_SNAPSHOT","V5_8_1","V5_8_2_SNAPSHOT","V5_8_2","V5_8_3_SNAPSHOT","V5_8_3","V5_8_4_SNAPSHOT","V5_8_4","V5_8_5_SNAPSHOT","V5_8_5","V5_8_6_SNAPSHOT","V5_8_6","V5_8_7_SNAPSHOT","V5_8_7","V5_8_8_SNAPSHOT","V5_8_8","V5_8_9_SNAPSHOT","V5_8_9","V5_9_0_SNAPSHOT","V5_9_0","V5_9_1_SNAPSHOT","V5_9_1","V5_9_2_SNAPSHOT","V5_9_2","V5_9_3_SNAPSHOT","V5_9_3","V5_9_4_SNAPSHOT","V5_9_4","V5_9_5_SNAPSHOT","V5_9_5","V5_9_6_SNAPSHOT","V5_9_6","V5_9_7_SNAPSHOT","V5_9_7","V5_9_8_SNAPSHOT","V5_9_8","V5_9_9_SNAPSHOT","V5_9_9","HIGHER_VERSION"]

def is_ip_address(ip_address):
  try:
    ipaddress.ip_address(ip_address)
    return True
  except ValueError:
    return False
  


def dns_query(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        return f"An error occurred: {e}"

def detect_version(ip,port,data):
    parsed_data = data

    # extracting brokerAddrs
    broker_addrs = []
    for broker_name, broker_data in parsed_data['data']['clusterInfo']['brokerAddrTable'].items():
        broker_addrs.append(broker_data['brokerAddrs'])

    # extracting brokerVersionDesc
    broker_version_descs = []
    for broker_name, broker_data in parsed_data['data']['brokerServer'].items():
        for broker_id, broker_id_data in broker_data.items():
            broker_version_descs.append(broker_id_data['brokerVersionDesc'])

    for version in broker_version_descs:
        col1,col2,col3 = version[1:].split('_')
        version_str = col1 + '.' + col2 + '.' + col3
        version = int(col1)*100 + int(col2)*10 + int(col3)
        if (version > 500 and version < 511) or (version > 400 and version < 496):
            print('{ip}:{port} is an unauthorized RocketMQ dashboard and Vulnerable to CVE-2023-33246 RocketMQ RCE, broker addr: {broker_addrs}'.format(ip=ip ,port=port,version_str=version_str, broker_addrs=broker_addrs))
        else:
            print("{ip}:{port} NOT Vulnerable to CVE-2023-33246 RocketMQ RCE".format(ip=ip, port=port))

def is_rocketmq_dashboard(ip, port):
    try:
        resp = requests.get("http://{ip}:{port}/cluster/list.query".format(ip=ip, port=port), timeout=(5,5))
        if resp.status_code == 200 and 'json' in resp.headers['Content-Type']:
            data = resp.json()
            detect_version(ip,port,data)
        else:
            return False
    except Exception as e:
        # sys.stderr.write("{ip}:{port} is not reachable: {e}\n".format(ip=ip, port=port, e=e))
        return False
    
    return True

def send_data_to_broker(ip, port):
    resp = None
    data1 = '000000c7000000c37b22636f6465223a3130352c226578744669656c6473223a7b225369676e6174757265223a222f7535502f775a5562686a616e75344c4d2f557a45646f327532493d222c22746f706963223a22544257313032222c224163636573734b6579223a22726f636b65746d7132227d2c22666c6167223a302c226c616e6775616765223a224a415641222c226f7061717565223a312c2273657269616c697a655479706543757272656e74525043223a224a534f4e222c2276657273696f6e223a3430317d'
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        # Connect to the server at the specified IP and port
        s.connect((ip, port))

        # Send the payload
        s.sendall(bytes.fromhex(data1))
        resp = s.recv(1024)
        if  not resp:
            print("{ip} is not reachable, revice nothing from {port}.".format(ip=ip, port=port))
        # Close the socket
        s.close()
    except Exception as e:
        sys.stderr.write("{ip}:{port} is not reachable: {e}\n".format(ip=ip, port=port, e=e))
    return resp

def check_vulnerability(target):
    """Check if the target is vulnerable"""
    ip, port = target.get('ip'), int(target.get('port'))
    if not is_rocketmq_dashboard(ip, port):
        resp = send_data_to_broker(ip, port)
        broker_addr = []
        data = resp[8:].decode()
        if data.startswith('{'):
            if '}{' in data:
                p1,p2 = data.split('}{')
                p1 += '}'
                p2 = '{' + p2
                for b in range(0, 10):
                    if ':{'+str(b)+':' in p2:
                        p2 = p2.replace(':{'+str(b)+':', ':{"'+str(b)+'":')
                    if str(b)+':"' in p2:
                        p2 = p2.replace(str(b)+':"', '"'+str(b)+'":"')
                for broker_addrs in json.loads(p2).get('brokerDatas'):
                    for broker in broker_addrs.get('brokerAddrs').values():
                        broker_addr.append(broker)
            else:
                p1 = data
            status = json.loads(p1)
            version = int(status.get('version'))
            target_version = version_list[version].replace('_', '.')
            if target_version.startswith('V4.9.'):
                minior_version = int(target_version.split('.')[2])
                if minior_version < 6:
                    print("{ip}:{port} Vulnerable to CVE-2023-33246 RocketMQ RCE, version: {version}, brokers: {broker_addr}".format(ip=ip, port=port, version=target_version ,broker_addr=', '.join(broker_addr)))
                else:
                    print("{ip}:{port} Not vulnerable to CVE-2023-33246 RocketMQ RCE, version: {version} >= V4.9.6".format(ip=ip, port=port, version=target_version))
            elif target_version.startswith('V5.1.'):
                minior_version = int(target_version.split('.')[2])
                if minior_version < 1:
                    print("{ip}:{port} Vulnerable to CVE-2023-33246 RocketMQ RCE, version: {version}, brokers: {broker_addr}".format(ip=ip, port=port, version=target_version ,broker_addr=', '.join(broker_addr)))
                else:
                    print("{ip}:{port} Not Vulnerable to CVE-2023-33246 RocketMQ RCE, version: {version} >= V5.1.1".format(ip=ip, port=port, version=target_version))
            else:
                print("{ip}:{port} Not vulnerable to CVE-2023-33246 RocketMQ RCE, version: {version}".format(ip=ip, port=port, version=target_version))
        else:
            print("{ip}:{port} Not vulnerable to CVE-2023-33246 RocketMQ RCE".format(ip=ip, port=port))

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Check CVE-2023-33246 RocketMQ RCE vulnerability")
    parser.add_argument("--ip", help="A single IP address to check")
    parser.add_argument("--file", help="A file containing a list of IP addresses, one per line")
    parser.add_argument("--port", type=int, default=9876, help="The port number to use when connecting to the server (default is 9876)")
    parser.add_argument("--cidr", help="A CIDR range to scan (e.g. 1.2.3.0/24)")
    args = parser.parse_args()
    target_list = []

    if args.cidr:
        for ip in ipaddress.ip_network(args.cidr):
            target_list.append({'ip': str(ip), 'port': args.port})

    if args.ip:
        target_list.append({'ip': args.ip, 'port': args.port})
    if args.file:
        with open(args.file, "r", encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('http://'):
                    ip = urlparse(line).netloc.split(':')[0]
                    if not is_ip_address(ip):
                        ip = dns_query(ip)
                        if not is_ip_address(ip):
                            print("Can not resolve: {line}".format(line=line))
                            continue
                    port = urlparse(line).port
                    if not port:
                        port = 80
                    target_list.append({'ip': ip, 'port': port})
                elif ':' in line:
                    ip, port = line.split(':')
                    target_list.append({'ip': ip, 'port': port})
                else:
                    target_list.append({'ip': line, 'port': args.port})

    if not target_list:
        print("Please provide at least one IP address using --ip or --file")
        return

    with ThreadPoolExecutor() as executor:
        for target in target_list:
            executor.submit(check_vulnerability, target)

if __name__ == "__main__":
    main()
