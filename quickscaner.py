import socket
import csv
import concurrent.futures
import nmap
import sys
import re
import string
import argparse

# Default, Top 30, Top 50, and Top 100 ports for scanning
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 139, 161, 162, 443, 445, 465, 587, 1433, 3306, 4444, 5432, 3389, 5985, 6379]
TOP_30 = DEFAULT_PORTS + [8080, 8443, 5900, 11211, 9200, 27017, 1434, 389, 88, 110, 143]
TOP_50 = TOP_30 + [26, 135, 137, 138, 179, 2222, 2601, 2604, 3128, 4443, 5000, 5353, 5901, 6667, 8000, 8081, 8181]
TOP_100 = TOP_50 + [9000, 9999, 10000, 10001, 12345, 16000, 22222, 27018, 50000, 55000, 60000]
EXCLUDE_DEFAULTS = list(set(TOP_100) - set(DEFAULT_PORTS))
ALL_PORTS = list(range(1, 65536))  # Full range

# Function to clean and validate hostname before resolution
def clean_hostname(hostname):
    hostname = hostname.strip()
    hostname = "".join(c for c in hostname if c in string.printable)  # Remove hidden characters

    if not hostname:
        return None, "Empty hostname"
    if len(hostname) > 255:
        return None, "Too long"
    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        return None, "Invalid format"

    return hostname, None  # Return cleaned hostname

# Function to resolve host to IP
def resolve_host(hostname):
    hostname, error = clean_hostname(hostname)
    if error:
        return None, None, error

    try:
        ip = socket.gethostbyname(hostname)
        return hostname, ip, None
    except socket.gaierror:
        return hostname, None, "IP NOT FOUND"
    except UnicodeError:
        return hostname, None, "Bad characters in hostname"

# Function to scan a host for open ports
def scan_host(ip, ports):
    scanner = nmap.PortScanner()
    scan_results = {port: "filtered" for port in ports}

    try:
        scanner.scan(ip, arguments="-T5 --min-rtt-timeout 50ms --max-retries 2 --open", ports=",".join(map(str, ports)))

        for port in ports:
            if ip in scanner.all_hosts() and port in scanner[ip]['tcp']:
                scan_results[port] = scanner[ip]['tcp'][port]['state']
    except Exception as e:
        print(f"⚠️ Error scanning {ip}: {e}")

    return scan_results

# Function to process each host
def process_host(args):
    index, total, hostname, ports = args
    hostname, ip, error_message = resolve_host(hostname)

    if index % 5 == 0:
        progress = (index / total) * 100
        print(f"🔄 Progress: {index}/{total} hosts checked ({progress:.2f}% complete)")

    if not hostname or error_message == "IP NOT FOUND":
        return None

    if ip:
        scan_results = scan_host(ip, ports)
        return [hostname, ip] + [scan_results[port] for port in ports]
    else:
        return [hostname, error_message] + ["N/A"] * len(ports)

# Main function
def main(input_file, output_file, port_option):
    # Choose the port set
    if port_option == "default":
        ports = DEFAULT_PORTS
    elif port_option == "top30":
        ports = TOP_30
    elif port_option == "top50":
        ports = TOP_50
    elif port_option == "top100":
        ports = TOP_100
    elif port_option == "exclude_default":
        ports = EXCLUDE_DEFAULTS
    elif port_option == "all":
        ports = ALL_PORTS
    else:
        print("Invalid port option. Use --help for valid options.")
        sys.exit(1)

    with open(input_file, "r", encoding="utf-8") as f:
        hostnames = [line.strip() for line in f if line.strip()]

    total_hosts = len(hostnames)
    results = []

    print(f"🚀 Starting scan for {total_hosts} hosts using {len(ports)} ports...")

    # Use ThreadPoolExecutor for concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for i, result in enumerate(executor.map(process_host, [(i + 1, total_hosts, h, ports) for i, h in enumerate(hostnames)])):
            if result:
                results.append(result)

            if i % 10 == 0 and results:
                print(f"✅ Last few results:\n{results[-3:]}")

    # Write results to CSV
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Hostname", "IP/Status"] + [f"Port {port}" for port in ports])
        writer.writerows(results)

    print(f"✅ Scan completed! {len(results)} hosts processed. Results saved to {output_file}")

# Run the script
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Quick Port Scanner with different port lists.")
    parser.add_argument("input_file", help="Input file with hostnames/FQDNs")
    parser.add_argument("output_file", help="Output CSV file for results")
    parser.add_argument("--ports", choices=["default", "top30", "top50", "top100", "exclude_default", "all"], default="default",
                        help="Port selection mode. Options: default, top30, top50, top100, exclude_default, all")

    args = parser.parse_args()
    main(args.input_file, args.output_file, args.ports)
