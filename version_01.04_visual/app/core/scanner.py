import asyncio
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import logging
import concurrent.futures

logger = logging.getLogger(__name__)

def parse_cidr(network_cidr: str) -> List[str]:
    """CIDR를 IP 리스트로 변환"""
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        logger.error(f"Invalid CIDR: {network_cidr}, Error: {e}")
        return []

def discover_alive_hosts(network_cidr: str, timeout: int = 300) -> List[str]:
    """Nmap -sn으로 살아있는 호스트 탐지"""
    print(f"[DISCOVERY] 🔍 Discovering alive hosts in {network_cidr}...")
    logger.info(f"[DISCOVERY] Starting host discovery for {network_cidr}")
    
    alive_hosts = []
    
    try:
        # Nmap Ping Scan
        result = subprocess.run(
            ["nmap", "-sn", "-oX", "-", network_cidr],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0:
            print(f"[DISCOVERY] ✗ Nmap failed: {result.stderr}")
            return []
        
        # XML 파싱
        root = ET.fromstring(result.stdout)
        
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                address = host.find('address')
                if address is not None:
                    ip = address.get('addr')
                    alive_hosts.append(ip)
                    print(f"[DISCOVERY] ✓ Found alive host: {ip}")
        
        print(f"[DISCOVERY] ✅ Found {len(alive_hosts)} alive hosts")
        logger.info(f"[DISCOVERY] Discovered {len(alive_hosts)} hosts")
        
    except subprocess.TimeoutExpired:
        print(f"[DISCOVERY] ✗ Discovery timeout after {timeout}s")
        logger.error(f"[DISCOVERY] Timeout after {timeout}s")
    except Exception as e:
        print(f"[DISCOVERY] ✗ Error: {e}")
        logger.error(f"[DISCOVERY] Error: {e}")
    
    return alive_hosts

def scan_single_host_sync(ip: str, ports: List[int] = [80, 443, 8080, 8000, 3000]) -> Dict[str, Any]:
    """
    단일 호스트 스캔 (동기 버전)
    
    Args:
        ip: 타겟 IP
        ports: 스캔할 포트 리스트
        
    Returns:
        스캔 결과
    """
    # 순환 import 방지: 함수 내부에서 import
    from ..api.routes import async_scan_workflow
    import asyncio
    
    print(f"[SCANNER] 🎯 Scanning {ip}...")
    logger.info(f"[SCANNER] Starting scan for {ip}")
    
    results = {
        "ip": ip,
        "scan_results": [],
        "total_cves": 0,
        "total_techs": 0
    }
    
    # 각 포트에 대해 스캔
    for port in ports:
        target = f"http://{ip}:{port}"
        
        try:
            # 새 이벤트 루프에서 실행
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = loop.run_until_complete(async_scan_workflow(target))
                
                if result and result.get('recon'):
                    technologies = []
                    for host in result.get('recon', []):
                        for port_info in host.get('ports', []):
                            technologies.append({
                                'product': port_info.get('product', 'Unknown'),
                                'version': port_info.get('version', 'N/A')
                            })
                    
                    cves = result.get('cves', [])
                    
                    if technologies or cves:
                        results["scan_results"].append({
                            "port": port,
                            "url": target,
                            "technologies": technologies,
                            "cves": cves
                        })
                        results["total_cves"] += len(cves)
                        results["total_techs"] += len(technologies)
                        
                        print(f"[SCANNER] ✓ {ip}:{port} - Found {len(technologies)} techs, {len(cves)} CVEs")
            finally:
                loop.close()
        
        except Exception as e:
            print(f"[SCANNER] ✗ {ip}:{port} - Error: {e}")
            logger.error(f"[SCANNER] Error scanning {ip}:{port}: {e}")
            continue
    
    return results

def run_network_scan(network_cidr: str, max_concurrent: int = 5) -> Dict[str, Any]:
    """
    네트워크 대역 전체 스캔 (ThreadPoolExecutor 사용)
    
    Args:
        network_cidr: 예) 192.168.1.0/24
        max_concurrent: 동시 실행 제한 (기본 5)
        
    Returns:
        전체 네트워크 스캔 결과
    """
    print("=" * 70)
    print(f"[NETWORK-SCAN] 🚀 Starting network scan: {network_cidr}")
    print(f"[NETWORK-SCAN] Max concurrent scans: {max_concurrent}")
    print("=" * 70)
    
    # 1단계: 살아있는 호스트 탐지
    alive_hosts = discover_alive_hosts(network_cidr)
    
    if not alive_hosts:
        print("[NETWORK-SCAN] ✗ No alive hosts found!")
        return {
            "network": network_cidr,
            "alive_hosts": 0,
            "scanned_hosts": 0,
            "results": []
        }
    
    # 2단계: ThreadPoolExecutor로 병렬 스캔
    print(f"[NETWORK-SCAN] 🔄 Starting parallel scan of {len(alive_hosts)} hosts...")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        future_to_ip = {executor.submit(scan_single_host_sync, ip): ip for ip in alive_hosts}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                results.append(result)
                print(f"[NETWORK-SCAN] ✓ Completed scan for {ip}")
            except Exception as e:
                print(f"[NETWORK-SCAN] ✗ Error scanning {ip}: {e}")
                logger.error(f"[NETWORK-SCAN] Error scanning {ip}: {e}")
    
    # 3단계: 결과 요약
    summary = {
        "network": network_cidr,
        "alive_hosts": len(alive_hosts),
        "scanned_hosts": len(results),
        "total_cves": sum(r.get("total_cves", 0) for r in results),
        "total_techs": sum(r.get("total_techs", 0) for r in results),
        "vulnerable_hosts": len([r for r in results if r.get("total_cves", 0) > 0]),
        "results": results
    }
    
    print("=" * 70)
    print(f"[NETWORK-SCAN] ✅ Network scan completed!")
    print(f"[NETWORK-SCAN] 📊 Summary:")
    print(f"  - Alive hosts: {summary['alive_hosts']}")
    print(f"  - Scanned hosts: {summary['scanned_hosts']}")
    print(f"  - Vulnerable hosts: {summary['vulnerable_hosts']}")
    print(f"  - Total CVEs: {summary['total_cves']}")
    print(f"  - Total technologies: {summary['total_techs']}")
    print("=" * 70)
    
    return summary
