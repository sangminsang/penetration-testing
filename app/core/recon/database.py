# app/core/recon/database.py
# 데이터베이스 정보 수집 모듈

import re
import socket
import logging
from typing import Dict, Any, List, Optional
import json

logger = logging.getLogger(__name__)


def analyze_mysql(target: str, port: int = 3306) -> Dict[str, Any]:
    """
    MySQL 상세 정보 분석 및 인증 우회 테스트
    
    Returns:
        {
            "version": "5.7.35",
            "anonymous_access": False,
            "weak_credentials": []
        }
    """
    mysql_info = {
        "version": None,
        "anonymous_access": False,
        "weak_credentials": []
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # MySQL 핸드셰이크 패킷에서 버전 정보 추출 시도
        data = sock.recv(1024)
        sock.close()
        
        # MySQL 핸드셰이크에서 버전 추출 (간단한 파싱)
        if data:
            version_match = re.search(r'(\d+\.\d+\.\d+)', data.decode('utf-8', errors='ignore'))
            if version_match:
                mysql_info["version"] = version_match.group(1)
        
        # 인증 우회 테스트 (pymysql 사용)
        try:
            import pymysql
            common_creds = [
                ("root", ""),
                ("root", "root"),
                ("admin", "admin"),
                ("mysql", "mysql"),
                ("", "")
            ]
            
            for username, password in common_creds:
                try:
                    conn = pymysql.connect(
                        host=target,
                        port=port,
                        user=username,
                        password=password,
                        connect_timeout=3
                    )
                    mysql_info["weak_credentials"].append({
                        "username": username or "(empty)",
                        "password": password or "(empty)",
                        "accessible": True
                    })
                    conn.close()
                    break
                except:
                    continue
        except ImportError:
            # pymysql이 없으면 스킵
            pass
            
    except Exception as e:
        logger.warning(f"MySQL 분석 실패 ({target}:{port}): {e}")
    
    return mysql_info


def analyze_postgresql(target: str, port: int = 5432) -> Dict[str, Any]:
    """
    PostgreSQL 상세 정보 분석 및 인증 우회 테스트
    
    Returns:
        {
            "version": "13.4",
            "anonymous_access": False,
            "weak_credentials": []
        }
    """
    postgres_info = {
        "version": None,
        "anonymous_access": False,
        "weak_credentials": []
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # PostgreSQL 프로토콜에서 버전 정보 추출 시도
        data = sock.recv(1024)
        sock.close()
        
        if data:
            version_match = re.search(r'PostgreSQL (\d+\.\d+)', data.decode('utf-8', errors='ignore'))
            if version_match:
                postgres_info["version"] = version_match.group(1)
        
        # 인증 우회 테스트 (psycopg2 사용)
        try:
            import psycopg2
            common_creds = [
                ("postgres", "postgres"),
                ("postgres", ""),
                ("admin", "admin"),
                ("", "")
            ]
            
            for username, password in common_creds:
                try:
                    conn = psycopg2.connect(
                        host=target,
                        port=port,
                        user=username or "postgres",
                        password=password,
                        connect_timeout=3
                    )
                    postgres_info["weak_credentials"].append({
                        "username": username or "(empty)",
                        "password": password or "(empty)",
                        "accessible": True
                    })
                    conn.close()
                    break
                except:
                    continue
        except ImportError:
            # psycopg2가 없으면 스킵
            pass
            
    except Exception as e:
        logger.warning(f"PostgreSQL 분석 실패 ({target}:{port}): {e}")
    
    return postgres_info


def analyze_mongodb(target: str, port: int = 27017) -> Dict[str, Any]:
    """
    MongoDB 상세 정보 분석 및 인증 없이 접근 가능한지 체크
    
    Returns:
        {
            "version": "4.4.0",
            "anonymous_access": True,
            "databases": ["admin", "test"]
        }
    """
    mongodb_info = {
        "version": None,
        "anonymous_access": False,
        "databases": []
    }
    
    try:
        # pymongo로 상세 분석
        try:
            from pymongo import MongoClient
            from pymongo.errors import ServerSelectionTimeoutError, OperationFailure
            
            client = MongoClient(
                f'mongodb://{target}:{port}/',
                serverSelectionTimeoutMS=5000,
                socketTimeoutMS=5000
            )
            
            # 서버 정보 가져오기 (인증 없이 시도)
            server_info = client.server_info()
            mongodb_info["version"] = server_info.get("version")
            
            # 데이터베이스 목록 가져오기
            try:
                databases = client.list_database_names()
                mongodb_info["databases"] = databases
                mongodb_info["anonymous_access"] = True
            except OperationFailure:
                mongodb_info["anonymous_access"] = False
            
            client.close()
        except ImportError:
            # pymongo가 없으면 소켓으로만 시도
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            data = sock.recv(1024)
            sock.close()
            
            if data:
                version_match = re.search(r'(\d+\.\d+\.\d+)', data.decode('utf-8', errors='ignore'))
                if version_match:
                    mongodb_info["version"] = version_match.group(1)
        except (ServerSelectionTimeoutError, Exception) as e:
            logger.warning(f"MongoDB 상세 분석 실패 ({target}:{port}): {e}")
            
    except Exception as e:
        logger.warning(f"MongoDB 분석 실패 ({target}:{port}): {e}")
    
    return mongodb_info


def analyze_redis(target: str, port: int = 6379) -> Dict[str, Any]:
    """
    Redis INFO 명령어로 상세 분석
    
    Returns:
        {
            "version": "6.2.0",
            "os": "Linux",
            "memory": "1.2M",
            "auth_required": False,
            "dangerous": True
        }
    """
    redis_info = {
        "version": None,
        "os": None,
        "memory": None,
        "auth_required": False,
        "dangerous": False
    }
    
    try:
        import redis
        r = redis.Redis(
            host=target,
            port=port,
            socket_timeout=5,
            socket_connect_timeout=5,
            decode_responses=True
        )
        
        # INFO 명령어로 모든 정보 가져오기
        info = r.info()
        
        redis_info["version"] = info.get("redis_version")
        redis_info["os"] = info.get("os")
        redis_info["memory"] = info.get("used_memory_human")
        
        # 여기까지 왔다면 인증이 필요 없음
        redis_info["auth_required"] = False
        redis_info["dangerous"] = True
        
        # CONFIG 명령어 시도 (매우 위험)
        try:
            config = r.config_get("*")
            redis_info["config_accessible"] = True
        except:
            redis_info["config_accessible"] = False
            
    except ImportError:
        # redis 라이브러리가 없으면 소켓으로만 시도
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # INFO 명령어 전송
            sock.send(b"INFO\n")
            data = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # 버전 추출
            version_match = re.search(r'redis_version:([\d.]+)', data)
            if version_match:
                redis_info["version"] = version_match.group(1)
                redis_info["auth_required"] = False
                redis_info["dangerous"] = True
        except:
            pass
    except Exception as e:
        logger.warning(f"Redis 분석 실패 ({target}:{port}): {e}")
    
    return redis_info


def analyze_elasticsearch(target: str, port: int = 9200) -> Dict[str, Any]:
    """
    Elasticsearch 클러스터 정보 및 인덱스 리스팅
    
    Returns:
        {
            "version": "7.15.0",
            "cluster": "elasticsearch",
            "indices_count": 5,
            "auth_required": False
        }
    """
    es_info = {
        "version": None,
        "cluster": None,
        "indices_count": 0,
        "auth_required": False
    }
    
    try:
        import requests
        base_url = f"http://{target}:{port}"
        
        # 버전 정보
        response = requests.get(
            base_url,
            timeout=5,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        
        if response.status_code == 200:
            data = response.json()
            es_info["version"] = data.get("version", {}).get("number")
            es_info["cluster"] = data.get("cluster_name")
            es_info["auth_required"] = False
            
            # 인덱스 리스팅 시도
            try:
                indices_resp = requests.get(
                    f"{base_url}/_cat/indices",
                    timeout=5,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if indices_resp.status_code == 200:
                    indices = indices_resp.text.strip().split('\n')
                    es_info["indices_count"] = len([i for i in indices if i])
            except:
                pass
                
    except Exception as e:
        logger.warning(f"Elasticsearch 분석 실패 ({target}:{port}): {e}")
    
    return es_info


def collect_database_info(target: str, nm_scan_result) -> Dict[str, Any]:
    """
    데이터베이스 서비스 정보 종합 수집
    
    Args:
        target: 타겟 호스트
        nm_scan_result: Nmap PortScanner 객체
    
    Returns:
        {
            "mysql_info": {...},
            "postgresql_info": {...},
            "mongodb_info": {...},
            "database_technologies": [...]
        }
    """
    logger.info("데이터베이스 정보 수집 시작")
    
    database_technologies = []
    
    # Nmap 결과에서 DB 포트 찾기
    db_ports = {
        3306: ("mysql", analyze_mysql),
        5432: ("postgresql", analyze_postgresql),
        27017: ("mongodb", analyze_mongodb),
        1433: ("mssql", None),  # SQL Server
        6379: ("redis", analyze_redis),
        9200: ("elasticsearch", analyze_elasticsearch),
        9300: ("elasticsearch", analyze_elasticsearch),  # Elasticsearch transport
    }
    
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port in db_ports:
                        db_type, analyzer = db_ports[port]
                        
                        if analyzer:
                            db_info = analyzer(host, port)
                            
                            # 버전 정보가 있거나 인증 우회가 가능하면 추가
                            if db_info.get("version") or db_info.get("anonymous_access") or db_info.get("weak_credentials"):
                                db_name = f"{db_type}"
                                if db_info.get("version"):
                                    db_name += f" {db_info['version']}"
                                
                                tech_info = {
                                    "type": "database",
                                    "name": db_name,
                                    "source": "Database Protocol",
                                    "port": port,
                                    "db_type": db_type
                                }
                                
                                # 추가 정보
                                if db_info.get("anonymous_access"):
                                    tech_info["anonymous_access"] = True
                                if db_info.get("weak_credentials"):
                                    tech_info["weak_credentials"] = db_info["weak_credentials"]
                                if db_info.get("databases"):
                                    tech_info["databases"] = db_info["databases"]
                                if db_info.get("dangerous"):
                                    tech_info["dangerous"] = True
                                
                                database_technologies.append(tech_info)
                        else:
                            # Nmap에서 이미 감지된 정보 사용
                            svc = nm_scan_result[host][proto][port]
                            product = svc.get("product", "")
                            version = svc.get("version", "")
                            
                            if product or version:
                                database_technologies.append({
                                    "type": "database",
                                    "name": f"{product} {version}".strip(),
                                    "source": "Nmap Scan",
                                    "port": port,
                                    "db_type": db_type
                                })
    except Exception as e:
        logger.warning(f"데이터베이스 정보 수집 실패: {e}")
    
    return {
        "database_technologies": database_technologies
    }

