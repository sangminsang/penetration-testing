import nmap
import re

def mask_ip(ip: str) -> str:
    # 192.168.0.10 -> 192.168.0.x 형태로 마스킹
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = "x"
        return ".".join(parts)
    return ip

def parse_service_version(product: str, version: str) -> str:
    if product and version:
        return f"{product} {version}"
    if product:
        return product
    return "unknown"

def run_recon(target: str, nmap_args: str = "-sV -Pn", mask: bool = True):
    nm = nmap.PortScanner()
    nm.scan(target, arguments=nmap_args)

    hosts = []
    for host in nm.all_hosts():
        host_ip = mask_ip(host) if mask else host
        host_data = {
            "ip": host_ip,
            "hostname": nm[host].hostname() or "",
            "state": nm[host].state(),
            "os": nm[host].get("osmatch", []),
            "ports": []
        }

        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                svc = nm[host][proto][port]
                service_name = svc.get("name", "")
                product = svc.get("product", "")
                version = svc.get("version", "")
                full_version = parse_service_version(product, version)

                host_data["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": svc.get("state", ""),
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "full_version": full_version
                })

        hosts.append(host_data)

    return hosts
