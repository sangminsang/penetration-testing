# app/core/recon/os.py
# OS 및 시스템 레벨 정보 수집 모듈

import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)
import nmap


def detect_os_from_nmap(nm_scan_result) -> Dict[str, Any]:
    """
    Nmap OS 핑거프린팅 결과에서 OS 정보 추출
    
    Returns:
        {
            "os_type": "Linux",
            "os_version": "3.2-4.9",
            "os_details": [...],
            "accuracy": 95
        }
    """
    os_info = {
        "os_type": None,
        "os_version": None,
        "os_details": [],
        "accuracy": 0
    }
    
    try:
        for host in nm_scan_result.all_hosts():
            osmatch = nm_scan_result[host].get("osmatch", [])
            if osmatch:
                # 가장 정확도가 높은 OS 정보 사용
                best_match = max(osmatch, key=lambda x: x.get("accuracy", 0))
                
                os_info["os_type"] = best_match.get("name", "").split()[0] if best_match.get("name") else None
                os_info["os_version"] = best_match.get("name", "")
                os_info["os_details"] = osmatch
                os_info["accuracy"] = best_match.get("accuracy", 0)
                break
    except Exception as e:
        logger.warning(f"OS 탐지 실패: {e}")
    
    return os_info


def detect_system_services(nm_scan_result) -> List[Dict[str, Any]]:
    """
    시스템 서비스 정보 수집 (SSH, 시스템 라이브러리 등)
    
    Returns:
        [
            {
                "service": "ssh",
                "version": "OpenSSH 7.4",
                "port": 22,
                "cpe": "cpe:2.3:a:openssh:openssh:7.4"
            }
        ]
    """
    system_services = []
    
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    svc = nm_scan_result[host][proto][port]
                    service_name = svc.get("name", "").lower()
                    
                    # 시스템 서비스만 필터링
                    if service_name in ["ssh", "sshd"]:
                        product = svc.get("product", "")
                        version = svc.get("version", "")
                        
                        system_services.append({
                            "service": "openssh",
                            "version": version or product,
                            "port": port,
                            "product": product,
                            "full_info": f"{product} {version}".strip()
                        })
    except Exception as e:
        logger.warning(f"시스템 서비스 탐지 실패: {e}")
    
    return system_services


def collect_os_info(nm_scan_result) -> Dict[str, Any]:
    """
    OS 및 시스템 레벨 정보 종합 수집
    
    Args:
        nm_scan_result: Nmap PortScanner 객체
    
    Returns:
        {
            "os_info": {...},
            "system_services": [...],
            "os_technologies": [...]
        }
    """
    logger.info("OS 정보 수집 시작")
    
    # OS 핑거프린팅
    os_info = detect_os_from_nmap(nm_scan_result)
    
    # 시스템 서비스 탐지
    system_services = detect_system_services(nm_scan_result)
    
    # OS 기술 스택 종합
    os_technologies = []
    
    if os_info.get("os_type"):
        os_technologies.append({
            "type": "operating_system",
            "name": os_info["os_version"] or os_info["os_type"],
            "source": "OS Fingerprinting",
            "accuracy": os_info.get("accuracy", 0)
        })
    
    for svc in system_services:
        os_technologies.append({
            "type": "system_service",
            "name": svc.get("full_info", ""),
            "source": "Nmap Scan",
            "port": svc.get("port")
        })
    
    return {
        "os_info": os_info,
        "system_services": system_services,
        "os_technologies": os_technologies
    }

