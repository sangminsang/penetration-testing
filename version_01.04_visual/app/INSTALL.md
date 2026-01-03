# 라이브러리 설치 가이드

## 문제 해결

IDE에서 보이는 import 오류는 대부분 라이브러리가 설치되지 않아서 발생합니다.

## 설치 방법

### 1. 모든 라이브러리 설치

```bash
pip install -r requirements.txt
```

### 2. 주요 라이브러리 개별 설치 (문제가 있을 경우)

```bash
# 필수 라이브러리
pip install Flask>=3.0.0
pip install python-nmap>=0.7.1
pip install requests>=2.31.0
pip install packaging>=23.0

# 비동기 HTTP (NVD API용)
pip install aiohttp>=3.9.0

# 데이터베이스 클라이언트 (선택적)
pip install pymysql>=1.0.0
pip install psycopg2-binary>=2.9.0
pip install pymongo>=4.0.0
pip install redis>=4.0.0

# 기타
pip install tqdm>=4.66.0
pip install PyJWT>=2.8.0
pip install urllib3>=2.0.0
pip install boto3>=1.28.0
pip install cvss>=3.1.0
```

## Import 경로 문제

`app.config` import 오류는 다음을 확인하세요:

1. **프로젝트 루트 확인**: `config.py` 파일이 프로젝트 루트에 있는지 확인
2. **Python 경로**: 프로젝트 루트가 Python 경로에 포함되어 있는지 확인
3. **가상환경**: 가상환경을 사용하는 경우 활성화되어 있는지 확인

## 확인 방법

```bash
# Python 경로 확인
python -c "import sys; print('\n'.join(sys.path))"

# 라이브러리 설치 확인
python -c "import flask; print('Flask:', flask.__version__)"
python -c "import nmap; print('nmap: OK')"
python -c "import aiohttp; print('aiohttp:', aiohttp.__version__)"
python -c "import redis; print('redis: OK')"
```

## IDE 설정 (VS Code / PyCharm)

- **Python 인터프리터**: 올바른 Python 환경 선택
- **PYTHONPATH**: 프로젝트 루트를 PYTHONPATH에 추가
- **가상환경**: 프로젝트의 가상환경을 선택


