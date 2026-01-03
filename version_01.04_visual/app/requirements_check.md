# 라이브러리 설치 확인

다음 명령어로 모든 라이브러리를 설치하세요:

```bash
pip install -r requirements.txt
```

## 주요 라이브러리

- **Flask** - 웹 프레임워크
- **python-nmap** - nmap 모듈 (import nmap으로 사용)
- **aiohttp** - 비동기 HTTP 클라이언트
- **redis** - Redis 클라이언트
- **pymysql, psycopg2-binary, pymongo** - 데이터베이스 클라이언트

## Import 경로 문제 해결

`app.config` import 오류는 상대 경로 fallback을 추가했습니다.
만약 여전히 문제가 있다면:

1. Python 경로 확인: `python -c "import sys; print(sys.path)"`
2. 프로젝트 루트를 PYTHONPATH에 추가
3. 또는 가상환경에서 실행


