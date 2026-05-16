// Homepage hero scan form: redirects to /headers with normalized URL
const form = document.getElementById('hero-scan');
const input = document.getElementById('hero-url-input');

if (form && input) {
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    let url = input.value.trim();
    if (!url) return;
    if (!/^https?:\/\//i.test(url)) {
      url = 'https://' + url;
    }
    window.location.href = `/headers?url=${encodeURIComponent(url)}`;
  });
}