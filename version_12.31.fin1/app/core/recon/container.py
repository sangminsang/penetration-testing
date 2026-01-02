# app/core/recon/container.py
# 컨테이너 정보 수집 모듈

import requests
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

def check_docker_api(target: str, port: int = 2375) -> Dict[str, Any]:
    """
    Docker API 노출 확인
    
    Returns:
        {
            "exposed": True,
            "version": "20.10.0",
            "containers": [...]
        }
    """
    docker_info = {
        "exposed": False,
        "version": None,
        "containers": []
    }
    
    try:
        url = f"http://{target}:{port}/version"
        response = requests.get(url, timeout=5, verify=False)
        
        if response.status_code == 200:
            docker_info["exposed"] = True
            data = response.json()
            docker_info["version"] = data.get("Version", "")
            
            # 컨테이너 목록 조회
            containers_url = f"http://{target}:{port}/containers/json"
            containers_resp = requests.get(containers_url, timeout=5, verify=False)
            if containers_resp.status_code == 200:
                docker_info["containers"] = containers_resp.json()
    except:
        pass
    
    return docker_info


def check_kubernetes_api(target: str, port: int = 6443) -> Dict[str, Any]:
    """
    Kubernetes API 노출 확인
    
    Returns:
        {
            "exposed": True,
            "version": "1.20.0"
        }
    """
    k8s_info = {
        "exposed": False,
        "version": None
    }
    
    try:
        url = f"https://{target}:{port}/version"
        response = requests.get(url, timeout=5, verify=False)
        
        if response.status_code == 200:
            k8s_info["exposed"] = True
            data = response.json()
            k8s_info["version"] = data.get("gitVersion", "")
    except:
        pass
    
    return k8s_info


def analyze_docker_api_deep(target: str, port: int = 2375) -> Dict[str, Any]:
    """
    Docker API 상세 정보 수집 (컨테이너, 이미지, 네트워크, 시크릿)
    
    Returns:
        {
            "containers": [...],
            "images": [...],
            "networks": [...],
            "secrets": [...],
            "exposed": True,
            "risk": "CRITICAL"
        }
    """
    docker_deep = {
        "containers": [],
        "images": [],
        "networks": [],
        "secrets": [],
        "exposed": False,
        "risk": "CRITICAL"
    }
    
    try:
        base_url = f"http://{target}:{port}"
        headers = {"User-Agent": "Mozilla/5.0"}
        
        # 실행 중인 컨테이너 (all=true로 중지된 것도 포함)
        try:
            containers_resp = requests.get(
                f"{base_url}/containers/json?all=true",
                timeout=5,
                verify=False,
                headers=headers
            )
            if containers_resp.status_code == 200:
                docker_deep["containers"] = containers_resp.json()
                docker_deep["exposed"] = True
        except:
            pass
        
        # 이미지 목록
        try:
            images_resp = requests.get(
                f"{base_url}/images/json",
                timeout=5,
                verify=False,
                headers=headers
            )
            if images_resp.status_code == 200:
                docker_deep["images"] = images_resp.json()
        except:
            pass
        
        # 네트워크 정보
        try:
            networks_resp = requests.get(
                f"{base_url}/networks",
                timeout=5,
                verify=False,
                headers=headers
            )
            if networks_resp.status_code == 200:
                docker_deep["networks"] = networks_resp.json()
        except:
            pass
        
        # 시크릿 정보 (매우 위험!)
        try:
            secrets_resp = requests.get(
                f"{base_url}/secrets",
                timeout=5,
                verify=False,
                headers=headers
            )
            if secrets_resp.status_code == 200:
                docker_deep["secrets"] = secrets_resp.json()
        except:
            pass
            
    except Exception as e:
        logger.warning(f"Docker API 상세 분석 실패 ({target}:{port}): {e}")
    
    return docker_deep


def analyze_k8s_api_deep(target: str, port: int = 6443) -> Dict[str, Any]:
    """
    Kubernetes API 상세 분석 (Pod, Service, ConfigMap, Secret)
    
    Returns:
        {
            "pods": [...],
            "services": [...],
            "configmaps": [...],
            "secrets": [...],
            "exposed": True,
            "risk": "CRITICAL"
        }
    """
    k8s_deep = {
        "pods": [],
        "services": [],
        "configmaps": [],
        "secrets": [],
        "exposed": False,
        "risk": "CRITICAL"
    }
    
    try:
        base_url = f"https://{target}:{port}"
        headers = {"User-Agent": "Mozilla/5.0"}
        
        endpoints = {
            "pods": "/api/v1/pods",
            "services": "/api/v1/services",
            "configmaps": "/api/v1/configmaps",
            "secrets": "/api/v1/secrets"  # 매우 위험!
        }
        
        for resource_type, endpoint in endpoints.items():
            try:
                resp = requests.get(
                    f"{base_url}{endpoint}",
                    timeout=5,
                    verify=False,
                    headers=headers
                )
                if resp.status_code == 200:
                    data = resp.json()
                    k8s_deep[resource_type] = data.get("items", [])
                    k8s_deep["exposed"] = True
            except:
                continue
                
    except Exception as e:
        logger.warning(f"Kubernetes API 상세 분석 실패 ({target}:{port}): {e}")
    
    return k8s_deep


def collect_container_info(target: str, nm_scan_result) -> Dict[str, Any]:
    """
    컨테이너 인프라 정보 종합 수집
    
    Args:
        target: 타겟 호스트
        nm_scan_result: Nmap PortScanner 객체
    
    Returns:
        {
            "docker_info": {...},
            "kubernetes_info": {...},
            "container_technologies": [...]
        }
    """
    logger.info("컨테이너 정보 수집 시작")
    
    container_technologies = []
    
    # Docker API 포트 확인
    docker_info = {}
    docker_deep = {}
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port in [2375, 2376]:  # Docker API 포트
                        docker_info = check_docker_api(host, port)
                        if docker_info.get("exposed"):
                            # 상세 정보 수집
                            docker_deep = analyze_docker_api_deep(host, port)
                            container_technologies.append({
                                "type": "container",
                                "name": f"Docker {docker_info.get('version', '')}",
                                "source": "Docker API",
                                "port": port,
                                "exposed": True,
                                "containers_count": len(docker_deep.get("containers", [])),
                                "images_count": len(docker_deep.get("images", [])),
                                "secrets_count": len(docker_deep.get("secrets", [])),
                                "risk": "CRITICAL"
                            })
                        break
    except Exception as e:
        logger.warning(f"Docker 정보 수집 실패: {e}")
    
    # Kubernetes API 확인
    k8s_info = {}
    k8s_deep = {}
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port in [6443, 8080]:  # Kubernetes API 포트
                        k8s_info = check_kubernetes_api(host, port)
                        if k8s_info.get("exposed"):
                            # 상세 정보 수집
                            k8s_deep = analyze_k8s_api_deep(host, port)
                            container_technologies.append({
                                "type": "container",
                                "name": f"Kubernetes {k8s_info.get('version', '')}",
                                "source": "Kubernetes API",
                                "port": port,
                                "exposed": True,
                                "pods_count": len(k8s_deep.get("pods", [])),
                                "services_count": len(k8s_deep.get("services", [])),
                                "secrets_count": len(k8s_deep.get("secrets", [])),
                                "risk": "CRITICAL"
                            })
                        break
    except Exception as e:
        logger.warning(f"Kubernetes 정보 수집 실패: {e}")
    
    return {
        "docker_info": docker_info,
        "docker_deep": docker_deep,
        "kubernetes_info": k8s_info,
        "kubernetes_deep": k8s_deep,
        "container_technologies": container_technologies
    }

