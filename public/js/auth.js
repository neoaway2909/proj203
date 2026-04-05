document.addEventListener('DOMContentLoaded', () => {
    // Check if on login page and already logged in
    const token = localStorage.getItem('token');
    const isLoginPage = window.location.pathname.includes('login.html');
    const isRoot = window.location.pathname === '/' || window.location.pathname === '/index.html';

    if (token) {
        if (isLoginPage) {
            window.location.href = '/index.html';
        }
    } else {
        if (!isLoginPage) {
            window.location.href = '/login.html';
        }
    }

    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errEl = document.getElementById('login-error');

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                if (res.ok) {
                    const data = await res.json();
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('user', JSON.stringify(data.user));
                    errEl.classList.add('hidden');
                    window.location.href = '/index.html';
                } else {
                    errEl.classList.remove('hidden');
                }
            } catch (error) {
                console.error('Login error', error);
                errEl.classList.remove('hidden');
            }
        });
    }

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = '/login.html';
        });
    }
});
