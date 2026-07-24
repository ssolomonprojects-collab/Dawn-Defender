document.addEventListener('DOMContentLoaded', () => {

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

    // Show a loading state on the submit button while a scan runs -
    // scans hit the ML model + heuristics and can take a couple seconds,
    // so this avoids the "did my click even register?" moment.
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', () => {
            const btn = form.querySelector('button[type="submit"]');
            if (!btn) return;
            btn.innerHTML = '<span class="btn-spinner"></span> Analyzing...';
            btn.classList.add('is-loading');
        });
    });

});
