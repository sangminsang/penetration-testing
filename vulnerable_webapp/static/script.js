/**
 * VulnBank - 모의해킹 연습용 취약한 웹 애플리케이션
 * 클라이언트 사이드 JavaScript
 * 
 * ⚠️ 경고: 이 코드에는 의도적인 취약점이 포함되어 있습니다!
 */

// DOM이 로드된 후 실행
document.addEventListener('DOMContentLoaded', function() {
    console.log('🏦 VulnBank 웹 애플리케이션이 로드되었습니다.');
    console.log('⚠️ 이 애플리케이션은 교육 목적의 취약한 웹사이트입니다.');
    
    // 취약점: 콘솔에 민감한 정보 노출
    console.log('📌 힌트: 개발자 도구를 사용하여 취약점을 탐색해보세요!');
    console.log('🔑 테스트 계정: admin/admin123, user1/password1');
    
    // 파일 업로드 미리보기
    initFileUploadPreview();
    
    // 비밀번호 확인 검증
    initPasswordConfirmation();
    
    // 송금 금액 포맷팅
    initAmountFormatting();
    
    // 모바일 메뉴 토글
    initMobileMenu();
});

/**
 * 파일 업로드 미리보기
 * 취약점: 파일 타입 검증이 클라이언트 사이드에서만 수행됨
 */
function initFileUploadPreview() {
    const fileInput = document.getElementById('profile_pic');
    const profilePic = document.querySelector('.profile-pic');
    
    if (fileInput && profilePic) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            
            if (file) {
                // 취약점: 클라이언트 사이드에서만 파일 타입 체크 (우회 가능)
                // const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
                // if (!allowedTypes.includes(file.type)) {
                //     alert('이미지 파일만 업로드 가능합니다.');
                //     return;
                // }
                
                const reader = new FileReader();
                reader.onload = function(e) {
                    profilePic.src = e.target.result;
                };
                reader.readAsDataURL(file);
                
                console.log('📤 업로드할 파일:', file.name, file.type, file.size + 'bytes');
            }
        });
    }
}

/**
 * 비밀번호 확인 검증
 * 취약점: 클라이언트 사이드 검증만 있고 서버 사이드 검증 없음
 */
function initPasswordConfirmation() {
    const passwordForm = document.querySelector('.password-form, .auth-form');
    const newPassword = document.getElementById('new_password') || document.getElementById('password');
    const confirmPassword = document.getElementById('confirm_password') || document.getElementById('password_confirm');
    
    if (passwordForm && newPassword && confirmPassword) {
        passwordForm.addEventListener('submit', function(e) {
            if (newPassword.value !== confirmPassword.value) {
                e.preventDefault();
                alert('비밀번호가 일치하지 않습니다.');
                confirmPassword.focus();
            }
            
            // 취약점: 비밀번호 강도 검사 없음
            // 실제로는 서버에서도 검증해야 함
        });
    }
}

/**
 * 송금 금액 포맷팅
 */
function initAmountFormatting() {
    const amountInput = document.getElementById('amount');
    
    if (amountInput) {
        amountInput.addEventListener('blur', function() {
            const value = parseInt(this.value);
            if (!isNaN(value) && value > 0) {
                console.log('💰 송금 금액:', value.toLocaleString() + '원');
            }
        });
    }
}

/**
 * 모바일 메뉴 토글
 */
function initMobileMenu() {
    // 모바일 메뉴 버튼이 있다면 토글 기능 추가
    const menuToggle = document.querySelector('.menu-toggle');
    const navMenu = document.querySelector('.nav-menu');
    
    if (menuToggle && navMenu) {
        menuToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
        });
    }
}

/**
 * 취약점: DOM 기반 XSS
 * URL 파라미터를 그대로 DOM에 삽입
 */
function displayUrlParameter() {
    const urlParams = new URLSearchParams(window.location.search);
    const message = urlParams.get('message');
    
    if (message) {
        // 취약점: innerHTML을 사용하여 XSS 가능
        const messageDiv = document.getElementById('user-message');
        if (messageDiv) {
            messageDiv.innerHTML = message;  // 취약점!
        }
    }
}

/**
 * 취약점: 쿠키 조작 함수 (공격자 사용 가능)
 */
function setCookie(name, value, days) {
    let expires = '';
    if (days) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expires = '; expires=' + date.toUTCString();
    }
    // 취약점: HttpOnly, Secure 플래그 없음
    document.cookie = name + '=' + (value || '') + expires + '; path=/';
}

function getCookie(name) {
    const nameEQ = name + '=';
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

/**
 * 관리자 권한 체크 (클라이언트 사이드)
 * 취약점: 클라이언트 사이드에서 권한 검사 (우회 가능)
 */
function checkAdminAccess() {
    const userRole = getCookie('user_role');
    
    // 취약점: 쿠키 값을 클라이언트에서 체크
    if (userRole === 'admin') {
        console.log('✅ 관리자 권한이 확인되었습니다.');
        return true;
    } else {
        console.log('❌ 관리자 권한이 없습니다.');
        console.log('💡 힌트: document.cookie = "user_role=admin" 을 시도해보세요!');
        return false;
    }
}

/**
 * 디버그 정보 출력 (개발용)
 * 취약점: 프로덕션에서 디버그 정보 노출
 */
function debugInfo() {
    console.group('🔍 디버그 정보');
    console.log('현재 URL:', window.location.href);
    console.log('쿠키:', document.cookie);
    console.log('세션 스토리지:', JSON.stringify(sessionStorage));
    console.log('로컬 스토리지:', JSON.stringify(localStorage));
    console.log('User Agent:', navigator.userAgent);
    console.groupEnd();
}

// 취약점: 전역 함수로 노출되어 콘솔에서 호출 가능
window.debugInfo = debugInfo;
window.checkAdminAccess = checkAdminAccess;
window.setCookie = setCookie;
window.getCookie = getCookie;

/**
 * AJAX 요청 헬퍼 (취약점 포함)
 */
function makeRequest(url, method = 'GET', data = null) {
    return fetch(url, {
        method: method,
        // 취약점: CORS 헤더 없음, credentials 포함
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json'
        },
        body: data ? JSON.stringify(data) : null
    })
    .then(response => response.json())
    .catch(error => {
        // 취약점: 에러 정보 노출
        console.error('요청 실패:', error);
        throw error;
    });
}

// 페이지 로드 시 디버그 정보 출력 (개발 모드에서만)
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    debugInfo();
}










