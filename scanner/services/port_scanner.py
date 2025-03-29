import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from django.utils import timezone

# Common ports and their services
port_protocols = {
    21: ('FTP', 'File Transfer Protocol'),
    22: ('SSH', 'Secure Shell'),
    23: ('Telnet', 'Telnet'),
    25: ('SMTP', 'Simple Mail Transfer Protocol'),
    53: ('DNS', 'Domain Name System'),
    80: ('HTTP', 'Hypertext Transfer Protocol'),
    110: ('POP3', 'Post Office Protocol v3'),
    115: ('SFTP', 'Secure File Transfer Protocol'),
    135: ('RPC', 'Remote Procedure Call'),
    139: ('NetBIOS', 'NetBIOS Session Service'),
    143: ('IMAP', 'Internet Message Access Protocol'),
    194: ('IRC', 'Internet Relay Chat'),
    443: ('HTTPS', 'HTTP Secure'),
    445: ('SMB', 'Server Message Block'),
    1433: ('MSSQL', 'Microsoft SQL Server'),
    1521: ('Oracle', 'Oracle Database'),
    3306: ('MySQL', 'MySQL Database'),
    3389: ('RDP', 'Remote Desktop Protocol'),
    5432: ('PostgreSQL', 'PostgreSQL Database'),
    5900: ('VNC', 'Virtual Network Computing'),
    8080: ('HTTP-Proxy', 'HTTP Proxy'),
    8443: ('HTTPS-Alt', 'HTTPS Alternate')
}

def is_open(ip_address, port, timeout=1):
    """Check if a port is open on the given IP address"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip_address, port))
        sock.close()
        return result == 0
    except (socket.gaierror, socket.error, socket.timeout):
        return False

def get_protocol_info(port):
    """Get protocol information for a port"""
    if port in port_protocols:
        return port_protocols[port][0]
    return "Unknown"

def scan_port(ip, port, timeout=1):
    """Scan a single port on the given IP address"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    is_open = result == 0
    
    service = ""
    if is_open:
        try:
            service = socket.getservbyport(port)
        except (socket.error, OSError):
            service = get_protocol_info(port)
    
    sock.close()
    return {
        'port': port,
        'status': 'open' if is_open else 'closed',
        'service': service if is_open else ""
    }

def scan_server_ports(server_id, port_range="1-1024", user_id=None, max_workers=50):
    """
    Scan ports on a server
    
    Args:
        server_id: ID of the server to scan
        port_range: Range of ports to scan (e.g., "1-1024" or "22,80,443")
        user_id: ID of the user who initiated the scan
        max_workers: Maximum number of concurrent threads
        
    Returns:
        PortScan object with results
    """
    try:
        from scanner.models import Server, PortScan, PortScanResult
        server = Server.objects.get(id=server_id)
    except Server.DoesNotExist:
        return None
    
    # Parse port range
    ports_to_scan = []
    if "," in port_range:
        # Comma-separated list of ports
        ports_to_scan = [int(p.strip()) for p in port_range.split(",")]
    elif "-" in port_range:
        # Range of ports
        start, end = map(int, port_range.split("-"))
        ports_to_scan = range(start, end + 1)
    else:
        # Single port
        ports_to_scan = [int(port_range)]
    
    # Create port scan record
    port_scan = PortScan.objects.create(
        server=server,
        port_range=port_range,
        created_by_id=user_id
    )
    
    # Scan ports using thread pool
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, server.ip_address, port): port 
            for port in ports_to_scan
        }
        
        for future in future_to_port:
            try:
                result = future.result()
                results.append(result)
                
                # Save result to database
                PortScanResult.objects.create(
                    port_scan=port_scan,
                    port_number=result['port'],
                    status=result['status'],
                    service=result['service']
                )
            except Exception as e:
                print(f"Error scanning port: {e}")
    
    # Update server's last_scanned timestamp
    server.last_scanned = timezone.now()
    server.save()
    
    return port_scan

