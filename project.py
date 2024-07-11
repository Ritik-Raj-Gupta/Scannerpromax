import argparse
import nmap
import requests
import json


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

def check_vulnerabilities(open_ports):
	cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	for port_i in open_ports:
		keyword = port_i['product']+' '+port_i['version']
		params = {
			'keywordSearch': keyword,
			'resultsPerPage': 5
		}
		response = requests.get(cve_url, params=params)
		if response.status_code == 200:
			data = json.loads(response.text)
			if data['vulnerabilities']:
				for vuln in data['vulnerabilities']:
					print('-'*60)
					des = vuln['cve']['descriptions'][0]['value']
					print(keyword,": ",des)
			else:
				print("-"*60)
				print("No known vulnerabilities found for "+keyword)
		elif response.status_code == 403:
			pass
		else:
			print("-"*60)
			print(f"Error: {response.status_code}")
	print('-'*60)

def main():
	args = parse_arguments()
	ip_address = args.ip_address
	open_ports = scan_open_ports(ip_address)
	
	print(f"Open ports for {ip_address}:")
	for port_info in open_ports:
		print(f"Port: {port_info['port']}, Service: {port_info['name']}, Product: {port_info['product']}, Version: {port_info['version']}")
	vulnerabilities = check_vulnerabilities(open_ports)

if __name__ == "__main__":
	main()
