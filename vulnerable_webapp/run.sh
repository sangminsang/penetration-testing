#!/bin/bash

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║   🏦 VulnBank - 모의해킹 연습용 취약한 웹 애플리케이션       ║"
echo "║                                                              ║"
echo "║   ⚠️  경고: 이 애플리케이션은 교육 목적으로만 사용하세요!    ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "[*] Python 버전 확인 중..."
python3 --version || python --version
if [ $? -ne 0 ]; then
    echo "[!] Python이 설치되어 있지 않습니다."
    echo "[!] sudo apt install python3 python3-pip 명령으로 설치하세요."
    exit 1
fi

echo ""
echo "[*] 필요한 패키지 설치 중..."
pip3 install -r requirements.txt || pip install -r requirements.txt

echo ""
echo "[*] VulnBank 서버 시작 중..."
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo " 접속 URL: http://localhost:5000"
echo " 또는:     http://$(hostname -I | awk '{print $1}'):5000"
echo ""
echo " 테스트 계정:"
echo "   - admin / admin123 (관리자)"
echo "   - user1 / password1 (일반 사용자)"
echo "   - testuser / test1234 (테스트)"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "서버를 종료하려면 Ctrl+C를 누르세요."
echo ""

python3 app.py || python app.py










