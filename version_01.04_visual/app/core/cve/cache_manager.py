# app/core/cve/cache_manager.py
# 영구 캐시 매니저 (SQLite/Redis)

import json
import time
import logging
import sqlite3
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class CacheManager:
    """
    CVE 캐시 매니저
    - 메모리 캐시 (1차: 빠름)
    - 영구 캐시 (2차: 재시작 후에도 유지)
    - TTL 지원
    """
    
    def __init__(
        self,
        backend="sqlite",
        ttl=86400,  # 24시간
        db_path="data/cve_cache.db"
    ):
        """
        Args:
            backend: "memory", "sqlite", "redis"
            ttl: Time-to-live (초), 기본 24시간
            db_path: SQLite DB 경로
        """
        self.backend = backend
        self.ttl = ttl
        self.memory_cache = {}
        self.conn = None
        self.redis_client = None
        
        if backend == "sqlite":
            self._init_sqlite(db_path)
        elif backend == "redis":
            self._init_redis()
        
        logger.info(f"CacheManager initialized (backend={backend}, ttl={ttl}s)")
    
    def _init_sqlite(self, db_path: str):
        """SQLite 캐시 초기화"""
        # 디렉토리 생성
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_expires_at ON cve_cache(expires_at)
        """)
        self.conn.commit()
        logger.info(f"SQLite cache initialized: {db_path}")
    
    def _init_redis(self):
        """Redis 캐시 초기화"""
        try:
            import redis
            self.redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True
            )
            # 연결 테스트
            self.redis_client.ping()
            logger.info("Redis cache initialized")
        except Exception as e:
            logger.error(f"Redis initialization failed: {e}")
            logger.warning("Falling back to memory-only cache")
            self.backend = "memory"
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        캐시 조회 (메모리 → 영구 순서)
        
        Args:
            key: 캐시 키
        
        Returns:
            캐시된 데이터 또는 None
        """
        # 1. 메모리 캐시 확인
        if key in self.memory_cache:
            data, expires_at = self.memory_cache[key]
            if time.time() < expires_at:
                logger.debug(f"Memory cache HIT: {key[:60]}...")
                return data
            else:
                # 만료된 캐시 삭제
                del self.memory_cache[key]
        
        # 2. 영구 캐시 확인
        if self.backend == "sqlite":
            return self._get_sqlite(key)
        elif self.backend == "redis":
            return self._get_redis(key)
        
        return None
    
    def _get_sqlite(self, key: str) -> Optional[Dict[str, Any]]:
        """SQLite에서 조회"""
        try:
            cursor = self.conn.execute(
                "SELECT value, expires_at FROM cve_cache WHERE key = ?",
                (key,)
            )
            row = cursor.fetchone()
            
            if row:
                value_json, expires_at = row
                
                # 만료 확인
                if time.time() < expires_at:
                    data = json.loads(value_json)
                    # 메모리 캐시에도 저장
                    self.memory_cache[key] = (data, expires_at)
                    logger.debug(f"SQLite cache HIT: {key[:60]}...")
                    return data
                else:
                    # 만료된 캐시 삭제
                    self.conn.execute("DELETE FROM cve_cache WHERE key = ?", (key,))
                    self.conn.commit()
                    logger.debug(f"SQLite cache EXPIRED: {key[:60]}...")
            
            return None
        
        except Exception as e:
            logger.error(f"SQLite get error: {e}")
            return None
    
    def _get_redis(self, key: str) -> Optional[Dict[str, Any]]:
        """Redis에서 조회"""
        try:
            value_json = self.redis_client.get(f"cve:{key}")
            if value_json:
                data = json.loads(value_json)
                # 메모리 캐시에도 저장
                expires_at = int(time.time() + self.ttl)
                self.memory_cache[key] = (data, expires_at)
                logger.debug(f"Redis cache HIT: {key[:60]}...")
                return data
            return None
        
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None
    
    def set(self, key: str, value: Dict[str, Any]):
        """
        캐시 저장 (메모리 + 영구)
        
        Args:
            key: 캐시 키
            value: 저장할 데이터
        """
        expires_at = int(time.time() + self.ttl)
        created_at = int(time.time())
        
        # 1. 메모리 캐시
        self.memory_cache[key] = (value, expires_at)
        
        # 2. 영구 캐시
        if self.backend == "sqlite":
            self._set_sqlite(key, value, expires_at, created_at)
        elif self.backend == "redis":
            self._set_redis(key, value)
        
        logger.debug(f"Cache SET: {key[:60]}...")
    
    def _set_sqlite(self, key: str, value: Dict[str, Any], expires_at: int, created_at: int):
        """SQLite에 저장"""
        try:
            value_json = json.dumps(value, ensure_ascii=False)
            self.conn.execute(
                "INSERT OR REPLACE INTO cve_cache (key, value, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (key, value_json, expires_at, created_at)
            )
            self.conn.commit()
        except Exception as e:
            logger.error(f"SQLite set error: {e}")
    
    def _set_redis(self, key: str, value: Dict[str, Any]):
        """Redis에 저장"""
        try:
            value_json = json.dumps(value, ensure_ascii=False)
            self.redis_client.setex(
                f"cve:{key}",
                self.ttl,
                value_json
            )
        except Exception as e:
            logger.error(f"Redis set error: {e}")
    
    def clear_expired(self) -> int:
        """
        만료된 캐시 정리
        
        Returns:
            삭제된 캐시 수
        """
        current_time = int(time.time())
        deleted_count = 0
        
        # 메모리 캐시 정리
        expired_keys = [
            key for key, (_, expires_at) in self.memory_cache.items()
            if expires_at < current_time
        ]
        for key in expired_keys:
            del self.memory_cache[key]
            deleted_count += 1
        
        # 영구 캐시 정리
        if self.backend == "sqlite":
            try:
                cursor = self.conn.execute(
                    "DELETE FROM cve_cache WHERE expires_at < ?",
                    (current_time,)
                )
                self.conn.commit()
                deleted_count += cursor.rowcount
            except Exception as e:
                logger.error(f"SQLite clear_expired error: {e}")
        
        if deleted_count > 0:
            logger.info(f"Cleared {deleted_count} expired cache entries")
        
        return deleted_count
    
    def clear_all(self):
        """전체 캐시 삭제"""
        self.memory_cache.clear()
        
        if self.backend == "sqlite":
            try:
                self.conn.execute("DELETE FROM cve_cache")
                self.conn.commit()
                logger.info("All SQLite cache cleared")
            except Exception as e:
                logger.error(f"SQLite clear_all error: {e}")
        
        elif self.backend == "redis":
            try:
                for key in self.redis_client.scan_iter("cve:*"):
                    self.redis_client.delete(key)
                logger.info("All Redis cache cleared")
            except Exception as e:
                logger.error(f"Redis clear_all error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """캐시 통계"""
        stats = {
            "backend": self.backend,
            "ttl": f"{self.ttl}s",
            "memory_cache_size": len(self.memory_cache)
        }
        
        if self.backend == "sqlite":
            try:
                cursor = self.conn.execute("SELECT COUNT(*) FROM cve_cache")
                count = cursor.fetchone()[0]
                stats["sqlite_cache_size"] = count
            except Exception as e:
                logger.error(f"SQLite stats error: {e}")
        
        elif self.backend == "redis":
            try:
                count = len(list(self.redis_client.scan_iter("cve:*")))
                stats["redis_cache_size"] = count
            except Exception as e:
                logger.error(f"Redis stats error: {e}")
        
        return stats
    
    def __del__(self):
        """소멸자: 연결 종료"""
        if self.conn:
            self.conn.close()
