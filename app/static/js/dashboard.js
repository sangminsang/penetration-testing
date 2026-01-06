(() => {
    // 1. 소켓 안전 연결 (전역 window 객체 공유)
    if (!window.socket) {
        window.socket = io();
    }
    const socket = window.socket;

    document.addEventListener('DOMContentLoaded', () => {
        // 2. 안전장치: 대시보드 요소 확인
        const scanBtn = document.getElementById('scan-btn');
        const targetInput = document.getElementById('target-input');

        // 요소가 없으면 조용히 종료 (상세 페이지 등에서 에러 방지)
        if (!scanBtn || !targetInput) {
            // console.log('[INFO] Dashboard skipped (Not on dashboard page)');
            return;
        }

        console.log('[INIT] Dashboard initialized');

        // 3. 스캔 시작 로직
        scanBtn.addEventListener('click', () => {
            const target = targetInput.value.trim();
            if (!target) {
                alert('Please enter a valid URL');
                return;
            }

            scanBtn.disabled = true;
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';

            socket.emit('create_project', { target: target });
        });
    });

    // 4. 소켓 이벤트 리스너
    socket.on('project_created', (data) => {
        if (data.project_id) {
            console.log(`[SUCCESS] Project created: ${data.project_id}`);
            window.location.href = `/live-scan/${data.project_id}`;
        }
    });

    socket.on('error', (data) => {
        const scanBtn = document.getElementById('scan-btn');
        if (scanBtn) { // 버튼이 있는 경우에만 처리
            console.error('[ERROR]', data.message);
            scanBtn.disabled = false;
            scanBtn.innerHTML = 'Start Scan';
            alert('Error: ' + data.message);
        }
    });
})();
