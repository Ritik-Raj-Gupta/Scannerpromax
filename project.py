import argparse
import nmap
import requests
import json
import pyfiglet
import subprocess
import sys
import re
from urllib.parse import urlparse
from tqdm import tqdm

ascii_banner = pyfiglet.figlet_format("SCANNER\nPRO MAX")
print(ascii_banner)
print(f"------> Aanand Bathla | Ritik Raj Gupta")

def is_valid_ip(ip):
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    valid_ip = re.match(pattern, ip)
    return valid_ip

def is_valid_url(url):
    pattern = r'^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$'
    valid_url = re.match(pattern, url)
    return valid_url

def parse_arguments():
    parser = argparse.ArgumentParser(description='Scan an IP address for open ports and check for vulnerabilities.')
    parser.add_argument('target', type=str, help='The IP address or URL to scan.')
    args = parser.parse_args()
    if not (is_valid_ip(args.target) or is_valid_url(args.target)):
        raise ValueError("Invalid IP address or URL")
    return args

def get_host(target):
    if is_valid_url(target):
        return urlparse(target).netloc
    return target

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


def scan_open_ports(target):
	nm = nmap.PortScanner()
	nm.scan(get_host(target), arguments='-sV')
	open_ports = []
	for host in tqdm(nm.all_hosts(), desc="Scanning hosts", ascii=True, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}'):
		for proto in nm[host].all_protocols():
			ports = nm[host][proto].keys()
			for port in ports:
				service = nm[host][proto][port]
				open_ports.append({
					'port': port,
					'name': service['name'],
					'product': service['product'],
					'version': service['version']
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


def dir_scan(target):
	ip = get_host(target)
	sub_list = open("dirList.txt").read() 
	directories = sub_list.splitlines()

	for dir in tqdm(directories, desc="Scanning directories", ascii=True, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}'):
		dir_enum = f"http://{ip}/{dir}" 
		r = requests.get(dir_enum)
		if r.status_code==404: 
        		pass
		else:
			print("Valid directory:" ,dir_enum, "Status code:",r.status_code)


def sub_scan(target):
	ip = get_host(target)
	sub_list = open("subdomainlist.txt").read() 
	subdoms = sub_list.splitlines()

	for sub in tqdm(subdoms, desc="Scanning subdomains", ascii=True, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}'):
		sub_domains = f"http://{sub}.{ip}" 
		try:
			response = requests.get(sub_domains)
		except requests.ConnectionError: 
			pass
		if(response.ok):
			print(f"{response.url} found: Code-{response.status_code}")
		else:
			pass


def main():
	try:
		args = parse_arguments()
		target = args.target

		while True:
			print("\nChoose one of the option provided below to proceed!!")
			print("1.Check if the host is up")
			print("2.Port Scan")
			print("3.Vulnerability Scan")
			print("4.Directory Scan")
			print("5.Subdomain enumerator")
			print("99.Exit")
			ch = input("\nEnter you the number of your choice: ")
			
			if ch == '1':
				ping_ip(get_host(target))
				#function to ping the target
			elif ch == '2':
                		open_ports = scan_open_ports(target)
                		print(f"Open ports for {target}:")
                		for port_info in open_ports:
                			print(f"Port: {port_info['port']}, Service: {port_info['name']}, Product: {port_info['product'] if port_info['product']!='' else 'Unable to detect'}, Version: {port_info['version'] if port_info['version']!='' else 'Unable to detect' }")
			elif ch == '3':
				try:
					check_vulnerabilities(open_ports)
				except UnboundLocalError:
					print("Scan ports to identify open ports. Then retry!")
			elif ch == '4':
				dir_scan(target)
				#function to perform directory scan
			elif ch == '5':
				sub_scan(target)
				#function to perform Subdomain scan
			elif ch == '99':
				print("ThankYou for using!!\nExiting the program...")
				break
			else:
				print("\n\nNot a valid choice exiting the program...")
				break
	except KeyboardInterrupt:
		print("\nExiting program")

if __name__ == "__main__":
	main()
