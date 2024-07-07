import argparse
import nmap
import requests

def parse_arguments():
    parser = argparse.ArgumentParser(description='Scan an IP address for open ports and check for vulnerabilities.')
    parser.add_argument('ip_address', type=str, help='The IP address to scan.')
    return parser.parse_args()

def scan_open_ports(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-sV')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                open_ports.append({
                    'port': port,
                    'name': service['name'],
                    'product': service.get('product', ''),
                    'version': service.get('version', '')
                })
    return open_ports

def check_vulnerabilities(service_info):
    cve_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {
        'keyword': service_info['name'],
        'resultsPerPage': 5
    }
    response = requests.get(cve_url, params=params)
    if response.status_code == 200:
        return response.json().get('result', {}).get('CVE_Items', [])
    return []

def main():
    args = parse_arguments()
    ip_address = args.ip_address
    open_ports = scan_open_ports(ip_address)
    
    print(f"Open ports for {ip_address}:")
    for port_info in open_ports:
        print(f"Port: {port_info['port']}, Service: {port_info['name']}, Product: {port_info['product']}, Version: {port_info['version']}")
       # vulnerabilities = check_vulnerabilities(port_info)
       # if vulnerabilities:
           # print(f"Vulnerabilities for {port_info['name']}:")
           # for vulnerability in vulnerabilities:
              #  cve_id = vulnerability['cve']['CVE_data_meta']['ID']
              #  description = vulnerability['cve']['description']['description_data'][0]['value']
              #  print(f"CVE ID: {cve_id}, Description: {description}")
       # else:
           # print("No known vulnerabilities found.")

if __name__ == "__main__":
    main()
