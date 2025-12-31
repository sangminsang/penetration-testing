# app/core/recon/cloud.py
# 클라우드 인프라 정보 수집 모듈

import requests
import re
import json
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def check_s3_bucket(bucket_name: str) -> Dict[str, Any]:
    """
    S3 버킷 접근 가능 여부 확인
    
    Returns:
        {
            "exists": True,
            "public": True,
            "region": "us-east-1"
        }
    """
    s3_info = {
        "exists": False,
        "public": False,
        "region": None
    }
    
    # S3 버킷 URL 패턴
    s3_urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]
    
    for url in s3_urls:
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 403]:
                s3_info["exists"] = True
                s3_info["public"] = (response.status_code == 200)
                break
        except:
            continue
    
    return s3_info


def analyze_s3_bucket_policy(bucket_name: str) -> Dict[str, Any]:
    """
    S3 버킷 정책 및 ACL 분석
    
    Returns:
        {
            "bucket_policy": {...},
            "acl": {...},
            "public_access_block": {...},
            "security_issues": [...]
        }
    """
    policy_info = {
        "bucket_policy": None,
        "acl": None,
        "public_access_block": None,
        "security_issues": []
    }
    
    # boto3를 사용한 상세 분석 (자격 증명이 있는 경우)
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        
        try:
            s3_client = boto3.client('s3')
            
            # 버킷 정책 확인
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_info["bucket_policy"] = policy.get("Policy")
                
                # 정책에서 공개 접근 허용 여부 확인
                if policy_info["bucket_policy"]:
                    policy_json = json.loads(policy_info["bucket_policy"])
                    statements = policy_json.get("Statement", [])
                    for stmt in statements:
                        if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                            policy_info["security_issues"].append({
                                "type": "public_policy",
                                "severity": "HIGH",
                                "description": "버킷 정책에서 모든 사용자에게 접근 허용"
                            })
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    policy_info["security_issues"].append({
                        "type": "policy_error",
                        "severity": "INFO",
                        "description": f"정책 조회 실패: {e}"
                    })
            
            # ACL 확인
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                grants = acl.get("Grants", [])
                
                policy_info["acl"] = {
                    "grants": grants,
                    "public_read": False,
                    "public_write": False
                }
                
                for grant in grants:
                    grantee = grant.get("Grantee", {})
                    if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                        permission = grant.get("Permission")
                        if permission in ["READ", "READ_ACP"]:
                            policy_info["acl"]["public_read"] = True
                            policy_info["security_issues"].append({
                                "type": "public_acl_read",
                                "severity": "HIGH",
                                "description": "ACL에서 모든 사용자에게 읽기 권한 부여"
                            })
                        if permission in ["WRITE", "WRITE_ACP", "FULL_CONTROL"]:
                            policy_info["acl"]["public_write"] = True
                            policy_info["security_issues"].append({
                                "type": "public_acl_write",
                                "severity": "CRITICAL",
                                "description": "ACL에서 모든 사용자에게 쓰기 권한 부여"
                            })
            except ClientError as e:
                policy_info["security_issues"].append({
                    "type": "acl_error",
                    "severity": "INFO",
                    "description": f"ACL 조회 실패: {e}"
                })
            
            # 퍼블릭 접근 차단 설정 확인
            try:
                public_access = s3_client.get_public_access_block(Bucket=bucket_name)
                policy_info["public_access_block"] = public_access.get("PublicAccessBlockConfiguration", {})
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                    policy_info["security_issues"].append({
                        "type": "public_access_block_error",
                        "severity": "INFO",
                        "description": f"퍼블릭 접근 차단 설정 조회 실패: {e}"
                    })
            
        except NoCredentialsError:
            policy_info["security_issues"].append({
                "type": "no_credentials",
                "severity": "INFO",
                "description": "AWS 자격 증명이 없어 상세 분석 불가 (HTTP 요청으로만 확인)"
            })
            
    except ImportError:
        # boto3가 없으면 HTTP 요청으로만 확인
        policy_info["security_issues"].append({
            "type": "boto3_missing",
            "severity": "INFO",
            "description": "boto3가 설치되지 않아 상세 분석 불가 (HTTP 요청으로만 확인)"
        })
        
        # HTTP 요청으로 버킷 접근 가능 여부만 확인
        s3_info = check_s3_bucket(bucket_name)
        if s3_info["public"]:
            policy_info["security_issues"].append({
                "type": "public_access",
                "severity": "HIGH",
                "description": "HTTP 요청으로 버킷에 공개 접근 가능"
            })
    
    return policy_info


def check_azure_blob(account_name: str, container_name: str = None) -> Dict[str, Any]:
    """
    Azure Blob Storage 접근 가능 여부 확인
    
    Returns:
        {
            "exists": True,
            "public": True
        }
    """
    azure_info = {
        "exists": False,
        "public": False
    }
    
    if container_name:
        url = f"https://{account_name}.blob.core.windows.net/{container_name}"
    else:
        url = f"https://{account_name}.blob.core.windows.net"
    
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code in [200, 403]:
            azure_info["exists"] = True
            azure_info["public"] = (response.status_code == 200)
    except:
        pass
    
    return azure_info


def check_gcp_storage(bucket_name: str) -> Dict[str, Any]:
    """
    Google Cloud Storage 접근 가능 여부 확인
    
    Returns:
        {
            "exists": True,
            "public": True
        }
    """
    gcp_info = {
        "exists": False,
        "public": False
    }
    
    url = f"https://storage.googleapis.com/{bucket_name}"
    
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code in [200, 403]:
            gcp_info["exists"] = True
            gcp_info["public"] = (response.status_code == 200)
    except:
        pass
    
    return gcp_info


def discover_cloud_assets(target: str) -> Dict[str, Any]:
    """
    클라우드 자산 발견 (S3, Azure, GCP)
    
    Args:
        target: 타겟 도메인 (예: "example.com")
    
    Returns:
        {
            "s3_buckets": [...],
            "azure_blobs": [...],
            "gcp_buckets": [...],
            "cloud_technologies": [...]
        }
    """
    logger.info("클라우드 자산 발견 시작")
    
    cloud_technologies = []
    
    # 도메인에서 추출 가능한 버킷 이름 패턴
    domain_parts = target.replace("www.", "").split(".")
    base_name = domain_parts[0] if domain_parts else target
    
    # 일반적인 버킷 이름 패턴
    bucket_candidates = [
        base_name,
        f"{base_name}-backup",
        f"{base_name}-dev",
        f"{base_name}-staging",
        f"{base_name}-prod",
        f"{base_name}-test",
        f"{base_name}-assets",
        f"{base_name}-static",
    ]
    
    s3_buckets = []
    for bucket_name in bucket_candidates[:5]:  # 처음 5개만 체크
        s3_info = check_s3_bucket(bucket_name)
        if s3_info["exists"]:
            # 버킷 정책 및 ACL 분석
            policy_info = analyze_s3_bucket_policy(bucket_name)
            
            s3_buckets.append({
                "name": bucket_name,
                "public": s3_info["public"],
                "policy_info": policy_info
            })
            
            tech_info = {
                "type": "cloud_storage",
                "name": f"AWS S3: {bucket_name}",
                "source": "Cloud Asset Discovery",
                "public": s3_info["public"]
            }
            
            # 보안 이슈가 있으면 추가
            if policy_info.get("security_issues"):
                tech_info["security_issues"] = policy_info["security_issues"]
                tech_info["risk"] = "HIGH" if any(issue.get("severity") in ["HIGH", "CRITICAL"] for issue in policy_info["security_issues"]) else "MEDIUM"
            
            cloud_technologies.append(tech_info)
    
    return {
        "s3_buckets": s3_buckets,
        "cloud_technologies": cloud_technologies
    }


def check_cloud_metadata(target: str) -> Dict[str, Any]:
    """
    클라우드 메타데이터 서비스 확인 (SSRF 시뮬레이션)
    AWS, Azure, GCP 메타데이터 엔드포인트 체크
    
    Returns:
        {
            "aws_metadata": {...},
            "azure_metadata": {...},
            "gcp_metadata": {...}
        }
    """
    metadata_info = {
        "aws_metadata": {"accessible": False, "endpoint": None},
        "azure_metadata": {"accessible": False, "endpoint": None},
        "gcp_metadata": {"accessible": False, "endpoint": None}
    }
    
    metadata_endpoints = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        ]
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Metadata-Flavor": "Google"  # GCP용
    }
    
    # AWS 메타데이터 확인
    try:
        for endpoint in metadata_endpoints["aws"]:
            try:
                resp = requests.get(
                    endpoint,
                    timeout=3,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if resp.status_code == 200:
                    metadata_info["aws_metadata"]["accessible"] = True
                    metadata_info["aws_metadata"]["endpoint"] = endpoint
                    break
            except:
                continue
    except:
        pass
    
    # Azure 메타데이터 확인
    try:
        for endpoint in metadata_endpoints["azure"]:
            try:
                resp = requests.get(
                    endpoint,
                    timeout=3,
                    verify=False,
                    headers={"Metadata": "true", "User-Agent": "Mozilla/5.0"}
                )
                if resp.status_code == 200:
                    metadata_info["azure_metadata"]["accessible"] = True
                    metadata_info["azure_metadata"]["endpoint"] = endpoint
                    break
            except:
                continue
    except:
        pass
    
    # GCP 메타데이터 확인
    try:
        for endpoint in metadata_endpoints["gcp"]:
            try:
                resp = requests.get(
                    endpoint,
                    timeout=3,
                    verify=False,
                    headers={"Metadata-Flavor": "Google", "User-Agent": "Mozilla/5.0"}
                )
                if resp.status_code == 200:
                    metadata_info["gcp_metadata"]["accessible"] = True
                    metadata_info["gcp_metadata"]["endpoint"] = endpoint
                    break
            except:
                continue
    except:
        pass
    
    return metadata_info


def collect_cloud_info(target: str) -> Dict[str, Any]:
    """
    클라우드 인프라 정보 종합 수집
    
    Args:
        target: 타겟 도메인
    
    Returns:
        {
            "cloud_assets": {...},
            "cloud_technologies": [...],
            "metadata_info": {...}
        }
    """
    cloud_assets = discover_cloud_assets(target)
    
    # 메타데이터 서비스 확인
    metadata_info = check_cloud_metadata(target)
    
    # 메타데이터 접근 가능하면 기술 스택에 추가
    if metadata_info["aws_metadata"]["accessible"]:
        cloud_assets["cloud_technologies"].append({
            "type": "cloud_metadata",
            "name": "AWS Metadata Service",
            "source": "Metadata Service Check",
            "accessible": True,
            "risk": "CRITICAL"
        })
    
    if metadata_info["azure_metadata"]["accessible"]:
        cloud_assets["cloud_technologies"].append({
            "type": "cloud_metadata",
            "name": "Azure Metadata Service",
            "source": "Metadata Service Check",
            "accessible": True,
            "risk": "CRITICAL"
        })
    
    if metadata_info["gcp_metadata"]["accessible"]:
        cloud_assets["cloud_technologies"].append({
            "type": "cloud_metadata",
            "name": "GCP Metadata Service",
            "source": "Metadata Service Check",
            "accessible": True,
            "risk": "CRITICAL"
        })
    
    return {
        "cloud_assets": cloud_assets,
        "cloud_technologies": cloud_assets.get("cloud_technologies", []),
        "metadata_info": metadata_info
    }

