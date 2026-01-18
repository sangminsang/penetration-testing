# 🖥️ VMware에서 VulnBank 실행 가이드

이 문서는 VMware 가상 머신에서 vulnerable_webapp을 실행하는 방법을 설명합니다.

---

## 📋 준비사항

1. **VMware 설치**
   - VMware Workstation Pro 또는 VMware Player
   - 또는 VMware Fusion (Mac)

2. **가상 머신 준비**
   - Linux 배포판 (Ubuntu 20.04 LTS 권장)
   - 또는 Windows 10/11 with WSL2

---

## 🚀 방법 1: Linux 가상 머신에서 실행

### 1단계: 가상 머신 설정

#### 네트워크 설정 (NAT 또는 Bridge)
1. VMware에서 가상 머신 선택
2. **Settings** → **Network Adapter**
3. **Network connection** 선택:
   - **NAT**: 호스트와 같은 네트워크 사용 (간단한 테스트용)
   - **Bridged**: 호스트와 동일한 네트워크에서 독립적인 IP (랩 환경용)

#### 메모리 및 리소스
- RAM: 최소 2GB (권장: 4GB)
- 디스크: 최소 10GB

### 2단계: 파일 전송

#### 방법 A: 공유 폴더 사용 (Windows 호스트)

1. **VMware 공유 폴더 설정**
   ```
   VMware 메뉴: VM → Settings → Options → Shared Folders
   - Always enabled 선택
   - Add: Windows 폴더 경로 추가
   ```

2. **Linux에서 마운트 확인**
   ```bash
   # 공유 폴더는 보통 /mnt/hgfs/ 아래에 마운트됨
   ls /mnt/hgfs/
   ```

3. **파일 복사**
   ```bash
   sudo cp -r /mnt/hgfs/shared_folder/vulnerable_webapp ~/
   ```

#### 방법 B: SCP 사용 (네트워크가 연결된 경우)

호스트(Windows)에서:
```powershell
# WSL2 또는 Git Bash에서 실행
scp -r "C:\Users\YONSAI\Desktop\새 폴더 (3)\vulnerable_webapp" user@VM_IP:/home/user/
```

#### 방법 C: USB 드라이브 사용

1. USB 드라이브를 가상 머신에 연결
   ```
   VMware 메뉴: VM → Removable Devices → USB → Connect
   ```
2. Linux에서 마운트
   ```bash
   sudo mkdir /mnt/usb
   sudo mount /dev/sdb1 /mnt/usb
   cp -r /mnt/usb/vulnerable_webapp ~/
   ```

### 3단계: 애플리케이션 설치 및 실행

#### Linux (Ubuntu/Debian)에서 실행

```bash
# 1. SSH 접속 (원격 접속 시)
ssh user@VM_IP

# 2. 필요한 패키지 설치
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

# 3. 프로젝트 디렉토리로 이동
cd ~/vulnerable_webapp

# 4. 가상환경 생성 (선택사항이지만 권장)
python3 -m venv venv
source venv/bin/activate

# 5. 패키지 설치
pip install -r requirements.txt

# 6. 실행 스크립트 권한 부여
chmod +x run.sh

# 7. 애플리케이션 실행
./run.sh
# 또는
python3 app.py
```

#### 실행 확인

```bash
# 터미널에 다음과 같은 메시지가 표시되어야 합니다:
#  * Running on all addresses (0.0.0.0)
#  * Running on http://127.0.0.1:5000
#  * Running on http://VM_IP:5000
```

### 4단계: 호스트에서 접속

#### VM의 IP 주소 확인

```bash
# Linux VM에서
hostname -I
# 또는
ip addr show
```

#### 호스트(Windows)에서 접속

1. **브라우저에서 접속**
   ```
   http://VM_IP:5000
   예: http://192.168.1.100:5000
   ```

2. **방화벽 확인 (Linux VM)**
   ```bash
   # UFW 방화벽이 활성화된 경우 포트 열기
   sudo ufw allow 5000/tcp
   sudo ufw status
   ```

---

## 🚀 방법 2: Windows 가상 머신에서 실행 (WSL2 사용)

### 1단계: WSL2 활성화

Windows VM에서:
```powershell
# PowerShell을 관리자 권한으로 실행
wsl --install
# Ubuntu 설치 확인
wsl --list --verbose
```

### 2단계: WSL2에서 실행

```bash
# WSL2 Ubuntu로 접속
wsl

# 프로젝트 디렉토리로 이동
cd /mnt/c/Users/YONSAI/Desktop/새\ 폴더\ \(3\)/vulnerable_webapp

# Python 설치 확인
python3 --version

# 패키지 설치
pip3 install -r requirements.txt

# 실행
python3 app.py
```

### 3단계: Windows에서 접속

```bash
# WSL2 IP 확인
hostname -I

# Windows 브라우저에서
# http://WSL_IP:5000
```

---

## 🔧 방법 3: 백그라운드 서비스로 실행 (systemd)

Linux VM에서 지속적으로 실행하려면:

### systemd 서비스 생성

```bash
# 서비스 파일 생성
sudo nano /etc/systemd/system/vulnbank.service
```

서비스 파일 내용:
```ini
[Unit]
Description=VulnBank Web Application
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/vulnerable_webapp
Environment="PATH=/home/YOUR_USERNAME/vulnerable_webapp/venv/bin"
ExecStart=/home/YOUR_USERNAME/vulnerable_webapp/venv/bin/python3 app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# 서비스 활성화 및 시작
sudo systemctl daemon-reload
sudo systemctl enable vulnbank
sudo systemctl start vulnbank

# 상태 확인
sudo systemctl status vulnbank

# 로그 확인
sudo journalctl -u vulnbank -f
```

---

## 🌐 네트워크 설정 상세

### NAT 모드 (기본)

- **장점**: 간단한 설정, 호스트 보호
- **단점**: 외부에서 VM에 직접 접근 불가
- **접속 방법**: 호스트에서만 `http://VM_IP:5000`

### Bridged 모드 (랩 환경 권장)

- **장점**: VM이 독립적인 IP를 가짐, 다른 기기에서도 접근 가능
- **단점**: 네트워크 설정 필요
- **접속 방법**: 같은 네트워크의 모든 기기에서 `http://VM_IP:5000`

#### Bridged 모드 설정

1. VMware: **VM → Settings → Network Adapter → Bridged**
2. Linux VM에서 고정 IP 설정 (선택사항):
   ```bash
   sudo nano /etc/netplan/01-netcfg.yaml
   ```
   ```yaml
   network:
     version: 2
     renderer: networkd
     ethernets:
       eth0:
         dhcp4: no
         addresses:
           - 192.168.1.100/24
         gateway4: 192.168.1.1
         nameservers:
           addresses: [8.8.8.8, 8.8.4.4]
   ```
   ```bash
   sudo netplan apply
   ```

### Host-only 모드

- **장점**: 호스트와 VM만 통신, 외부 네트워크 격리
- **접속 방법**: 호스트에서만 `http://VM_IP:5000`

---

## 🔥 빠른 시작 (Quick Start)

### 한 번에 실행하기

```bash
# 실행 스크립트 사용
cd vulnerable_webapp
chmod +x run.sh
./run.sh
```

### 실행 스크립트 (run.sh) 내용

```bash
#!/bin/bash
python3 --version
pip3 install -r requirements.txt
python3 app.py
```

---

## 🧪 접속 테스트

### 1. VM 내부에서 테스트

```bash
# VM 터미널에서
curl http://localhost:5000
```

### 2. 호스트에서 테스트

```powershell
# Windows PowerShell에서
Invoke-WebRequest -Uri http://VM_IP:5000
# 또는 브라우저에서 직접 접속
```

### 3. 네트워크 스캔 (다른 VM에서)

```bash
# Kali Linux 등에서
nmap -sV VM_IP
curl http://VM_IP:5000
```

---

## 📝 테스트 계정

애플리케이션 실행 후 다음 계정으로 로그인할 수 있습니다:

| 아이디 | 비밀번호 | 권한 | 잔액 |
|--------|----------|------|------|
| admin | admin123 | 관리자 | ₩999,999 |
| user1 | password1 | 일반 | ₩50,000 |
| user2 | password2 | 일반 | ₩30,000 |
| testuser | test1234 | 일반 | ₩15,000 |

---

## 🚨 트러블슈팅

### 문제 1: 포트 5000이 이미 사용 중

```bash
# 다른 포트로 변경 (app.py 수정)
# app.run(host='0.0.0.0', port=8080, debug=True)

# 또는 기존 프로세스 종료
sudo lsof -ti:5000 | xargs kill -9
```

### 문제 2: 호스트에서 접속 불가

```bash
# 1. 방화벽 확인
sudo ufw status
sudo ufw allow 5000/tcp

# 2. Flask가 0.0.0.0에서 리스닝하는지 확인
netstat -tlnp | grep 5000
# 또는
ss -tlnp | grep 5000

# 3. VM IP 확인
hostname -I
ip addr show
```

### 문제 3: 파일 전송 실패

```bash
# 공유 폴더가 마운트되지 않은 경우
sudo vmhgfs-fuse .host:/shared_folder /mnt/hgfs -o subtype=vmhgfs-fuse,allow_other

# 또는 GitHub 사용
git clone https://github.com/your-repo/vulnerable_webapp.git
```

### 문제 4: Python 패키지 설치 실패

```bash
# pip 업그레이드
python3 -m pip install --upgrade pip

# 가상환경 사용 (권장)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 문제 5: 네트워크 연결 안 됨

```bash
# VMware 네트워크 어댑터 재설정
# VMware: VM → Settings → Network Adapter
# - Remove
# - Add → Network Adapter → NAT 또는 Bridged

# Linux에서 네트워크 재시작
sudo systemctl restart networking
# 또는
sudo netplan apply
```

---

## 📚 추가 자료

- [README.md](README.md) - 기본 사용 가이드
- [DEPLOYMENT.md](DEPLOYMENT.md) - 프로덕션 배포 가이드
- [VULNERABILITIES.md](VULNERABILITIES.md) - 취약점 상세 설명

---

## ⚠️ 주의사항

1. **교육 목적으로만 사용**: 이 애플리케이션은 의도적으로 취약점이 포함되어 있습니다.
2. **격리된 환경에서 실행**: 프로덕션 네트워크와 분리된 환경에서만 사용하세요.
3. **방화벽 설정**: 실제 서비스와 분리하기 위해 적절한 방화벽 규칙을 설정하세요.

---

**Made for Educational Purposes Only** 🎓




