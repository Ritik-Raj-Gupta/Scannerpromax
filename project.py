import argparse
import nmap
import requests
import json
import pyfiglet
import subprocess
import sys


ascii_banner = pyfiglet.figlet_format("SCANNER\nPRO MAX")
print(ascii_banner)


def parse_arguments():
	parser = argparse.ArgumentParser(description='Scan an IP address for open ports and check for vulnerabilities.')
	parser.add_argument('ip_address', type=str, help='The IP address to scan.')
	return parser.parse_args()




def ping_ip(ip):
    	# Run the ping command
	result = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	output = result.stdout.decode('utf-8')
	error = result.stderr.decode('utf-8')

    	# Display the full output and error (if any)
	print("Output:")
	print(output)
	if error:
		print("Error:")
		print(error)
	# Check if the ping was successful
	if result.returncode == 0:
		print(f"{ip} is up")
	else:
		print(f"{ip} is down")


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
					idn = vuln['cve']['id']
					print(idn,"\n",keyword,": ",des)
			else:
				print("-"*60)
				print("No known vulnerabilities found for "+keyword)
		elif response.status_code == 403:
			pass
		else:
			print("-"*60)
			print(f"Error: {response.status_code}")
	print('-'*60)


def dir_scan(ip):
	sub_list = open("common.txt").read() 
	directories = sub_list.splitlines()

	for dir in directories:
		dir_enum = f"http://{ip}/{dir}" 
		r = requests.get(dir_enum)
		if r.status_code==404: 
        		pass
		else:
			print("Valid directory:" ,dir_enum, "Status code:",r.status_code)


def sub_scan(ip):
	
	sub_list = open("namelist.txt").read() 
	subdoms = sub_list.splitlines()

	for sub in subdoms:
		sub_domains = f"http://{sub}.{ip}" 

		try:
			requests.get(sub_domains)
    
		except requests.ConnectionError: 
			pass
    
		else:
			print("Subdomain found: ",sub_domains)



def main():
	args = parse_arguments()
	ip_address = args.ip_address
	open_ports = scan_open_ports(ip_address)

	while True:
		print("Choose one of the option provided below to proceed")
		print("1.Check if the host is up")
		print("2.Port Scan")
		print("3.Vulnerability Scan")
		print("4.Directory Scan")
		print("5.Subdomain enumerator")
		print("99.Exit")
		ch = input("\n\nEnter you the number of your choice")
		print("\n\n")
		if ch == '1':
			ping_ip(ip_address)
			#function to ping the target
		elif ch == '2':
			print(f"Open ports for {ip_address}:")
			for port_info in open_ports:
				print(f"Port: {port_info['port']}, Service: {port_info['name']}, Product: {port_info['product']}, Version: {port_info['version']}")
		elif ch == '3':
			check_vulnerabilities(open_ports)
		elif ch == '4':
			dir_scan(ip_address)
			#function to perform directory scan
		elif ch == '5':
			sub_scan(ip_address)
			#function to perform Subdomain scan
		elif ch == '99':
			print("Exiting the program...")
			break
		else:
			print("\n\nNot a valid choice exiting the program...")
			break


if __name__ == "__main__":
	main()
