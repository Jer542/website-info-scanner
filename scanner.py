import socket
import whois
import OpenSSL
import ssl
import concurrent.futures
from tqdm import tqdm
import sys
import requests
import dns.resolver

port_services = {
    20: 'FTP Data Transfer',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP Server',
    68: 'DHCP Client',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    123: 'NTP',
    137: 'NetBIOS Name Service',
    138: 'NetBIOS Datagram Service',
    139: 'NetBIOS Session Service',
    143: 'IMAP',
    161: 'SNMP',
    162: 'SNMP Trap',
    179: 'BGP',
    389: 'LDAP',
    443: 'HTTPS',
    465: 'SMTPS',
    500: 'ISAKMP',
    514: 'Syslog',
    520: 'RIP',
    546: 'DHCPv6 Client',
    547: 'DHCPv6 Server',
    587: 'SMTP',
    636: 'LDAPS',
    989: 'FTPS Data',
    990: 'FTPS Control',
    993: 'IMAPS',
    995: 'POP3S',
    1025: 'Microsoft RPC',
    1080: 'SOCKS Proxy',
    1194: 'OpenVPN',
    1433: 'Microsoft SQL Server',
    1701: 'L2TP',
    1723: 'PPTP',
    1812: 'RADIUS Authentication',
    1813: 'RADIUS Accounting',
    2082: 'cPanel',
    2083: 'cPanel over SSL',
    2086: 'WHM (Webhost Manager)',
    2087: 'WHM (Webhost Manager) over SSL',
    2095: 'Webmail',
    2096: 'Webmail over SSL',
    2483: 'Oracle Database',
    2484: 'Oracle Database',
    3306: 'MySQL',
    3389: 'Remote Desktop',
    5060: 'SIP',
    5061: 'SIP over TLS',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6001: 'X11',
    8008: 'HTTP Alternate',
    8080: 'HTTP-Proxy',
    8443: 'Plesk Control Panel',
    8888: 'News Server',
    27017: 'MongoDB',
}

def get_server_software(domain_name):
    try:
        response = requests.get(f"http://{domain_name}")
        return response.headers.get('Server')
    except Exception as e:
        print(f"Could not retrieve server software for {domain_name}: {e}")

def get_dns_records(domain_name):
    records = {}
    record_types = ['A', 'CNAME', 'MX', 'NS', 'SOA']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            records[record_type] = [str(answer) for answer in answers]
        except Exception:
            pass
    return records

def find_subdomains(domain_name):
    subdomains = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'dev', 'admin', 'portal', 'blog', 'vpn', 'shop', 'api', 'cdn', 'test', 'mx', 'pop', 'imap', 'cpanel', 'whm', 'webdisk', 'webmin', 'support', 'forum', 'direct', 'demo', 'beta', 'alpha', 'autodiscover', 'autoconfig', 'secure', 'public', 'private', 'staging', 'store', 'login', 'signup', 'account', 'billing']
    found_subdomains = []
    for subdomain in subdomains:
        try:
            dns.resolver.resolve(f"{subdomain}.{domain_name}", 'A')
            found_subdomains.append(subdomain)
        except Exception as e:
            pass
    return found_subdomains


def get_ssl_cert_info(host):
    cert = ssl.get_server_certificate((host, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    return x509.get_issuer()

def scan_ports(port, target_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            return port
    except Exception as e:
        print(f"Exception occurred while scanning port {port}: {e}")
    finally:
        sock.close()

def get_ssl_cert_info(host):
    cert = ssl.get_server_certificate((host, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    return x509.get_issuer()

def main():
    domain_names = input("Enter domain names (comma separated): ").split(',')
    while True:
        scan_option = input("Scan all ports or common ports for all domains? (all/common): ").lower()
        if scan_option == 'all':
            ports = range(1, 65536)
            break
        elif scan_option == 'common':
            ports = range(1, 1025)
            break
        elif scan_option == 'x':
            print("exiting...")
            sys.exit()
        else:
            print("Invalid option. Please enter 'all' or 'common'.")

    for domain_name in domain_names:
        domain_name = domain_name.strip()
        target_ip = socket.gethostbyname(domain_name)
        try:
            host_name = socket.gethostbyaddr(target_ip)[0]
        except socket.herror:
            host_name = target_ip
        print(f"\nScanning {domain_name} ({host_name}, {target_ip})")
        print(f"\nServer Software for {domain_name}: {get_server_software(domain_name)}")
        print(f"\nDNS Records for {domain_name}: {get_dns_records(domain_name)}")
        print(f"\nSubdomains for {domain_name}: {find_subdomains(domain_name)}")
        

        try:
            w = whois.whois(domain_name)
            print(f"\nWhois information for {domain_name}:")
            print(f"Domain Name: {w.domain_name}")
            print(f"Registrar: {w.registrar}")
            print(f"Creation Date: {w.creation_date[0].strftime('%Y-%m-%d %H:%M:%S') if isinstance(w.creation_date, list) else w.creation_date}")
            print(f"Expiration Date: {w.expiration_date[0].strftime('%Y-%m-%d %H:%M:%S') if isinstance(w.expiration_date, list) else w.expiration_date}")
            print(f"Last Updated: {w.updated_date[0].strftime('%Y-%m-%d %H:%M:%S') if isinstance(w.updated_date, list) else w.updated_date}")
        except Exception as e:
            print(f"Could not retrieve whois information for {domain_name}: {e}")


        try:
            issuer = get_ssl_cert_info(domain_name)
            print(f"\nSSL Certificate Issuer for {domain_name}:")
            print(f"Country: {issuer.countryName}")
            print(f"Organization Name: {issuer.organizationName}")
            print(f"Common Name: {issuer.commonName}")
        except Exception as e:
            print(f"Could not retrieve SSL certificate information for {domain_name}: {e}")

        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=5000) as executor:
            for port, result in tqdm(zip(ports, executor.map(lambda p: scan_ports(p, target_ip), ports)), total=len(ports), bar_format='{l_bar}%s{bar}%s{r_bar}' % ('\033[36m', '\033[0m')):
                if result:
                    open_ports.append(port)

        print(f"\nSummary for {domain_name}:")
        for port in open_ports:
            service = port_services.get(port, "Unknown service")
            print(f"Port {port} is open ({service})")

if __name__ == "__main__":
    main()
