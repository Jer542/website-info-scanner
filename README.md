# Port Scanner

This Python script is a comprehensive port scanner that not only scans for open ports on a given domain but also provides additional information about the domain such as server software, DNS records, subdomains, WHOIS information, and SSL certificate details.

## Features

- Scans all ports or common ports based on user input.
- Retrieves server software information.
- Retrieves DNS records.
- Finds potential subdomains.
- Retrieves WHOIS information.
- Retrieves SSL certificate information.
- Uses multithreading for efficient port scanning.

## Dependencies

This script requires the following Python libraries:

- socket
- whois
- OpenSSL
- ssl
- concurrent.futures
- tqdm
- sys
- requests
- dns.resolver

## Usage

Run the script in a Python environment. When prompted, enter the domain names you want to scan, separated by commas. Then, choose whether you want to scan all ports or just the common ports.

```bash
python scanner.py
```

## Output

The script will output the following information for each domain:

- Server software
- DNS records
- Subdomains
- WHOIS information
- SSL certificate issuer
- Open ports and their associated services

## Note

This script is intended for educational and legal use only. Do not use it to scan networks or domains without permission.
