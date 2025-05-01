import nmap
import sys

def nmap_scan(target, ports="1-1000"):
    # Initialize the Nmap scanner
    nm = nmap.PortScanner()
    
    try:
        # Perform the scan
        print(f"Scanning {target} for ports {ports}...")
        nm.scan(target, ports, arguments="-sS -sV")  # -sS for TCP SYN scan, -sV for version detection
        
        # Check if the host is up
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                print(f"\nHost: {host} ({nm[host].hostname()})")
                print(f"State: {nm[host].state()}")
                
                # Iterate through protocols (e.g., tcp, udp)
                for proto in nm[host].all_protocols():
                    print(f"\nProtocol: {proto}")
                    
                    # Get all scanned ports for the protocol
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        version = nm[host][proto][port].get('version', 'N/A')
                        print(f"Port: {port}\tState: {state}\tService: {service}\tVersion: {version}")
            else:
                print(f"\nHost: {host} is down")
                
    except nmap.PortScannerError as e:
        print(f"Error: Nmap scan failed - {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    # Check for command-line arguments
    if len(sys.argv) < 2:
        print("Usage: python nmap_scanner.py <target> [port_range]")
        print("Example: python nmap_scanner.py 192.168.1.1 1-1000")
        sys.exit(1)
    
    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else "1-1000"
    
    nmap_scan(target, ports)

if __name__ == "__main__":
    main()