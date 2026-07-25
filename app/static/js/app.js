document.addEventListener('DOMContentLoaded', () => {

    // Register PWA Service Worker for Chrome Android App mode
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/static/sw.js')
            .then(reg => console.log('[PWA] Service worker registered successfully.'))
            .catch(err => console.log('[PWA] Service worker registration error:', err));
    }

    // Mobile nav toggle
    const navToggle = document.querySelector('.nav-toggle');
    const navLinks = document.querySelector('.nav-links');
    if (navToggle && navLinks) {
        navToggle.addEventListener('click', () => {
            const isOpen = navLinks.classList.toggle('open');
            navToggle.setAttribute('aria-expanded', isOpen);
        });
        navLinks.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => navLinks.classList.remove('open'));
        });
    }

    // Submit button loading animation
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', () => {
            const btn = form.querySelector('button[type="submit"]');
            if (!btn) return;
            btn.innerHTML = '<span class="btn-spinner"></span> Analyzing...';
            btn.classList.add('is-loading');
        });
    });

    // Live Web File Access & Automatic APK Download Inspector
    const liveApkInput = document.getElementById('liveApkPicker');
    if (liveApkInput) {
        liveApkInput.addEventListener('change', (e) => {
            const files = e.target.files;
            if (files && files.length > 0) {
                const apkFile = files[0];
                if (apkFile.name.endsWith('.apk')) {
                    const form = liveApkInput.closest('form');
                    if (form) form.submit();
                }
            }
        });
    }
});
