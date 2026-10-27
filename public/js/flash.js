(function showFlashFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const messages = {
    registered: 'Account created. You can sign in now.',
    error: 'Login failed. Check the credentials or try the lab payload.',
    timeout: 'Your secure session timed out. Please sign in again.'
  };

  const key = Object.keys(messages).find((name) => params.has(name));
  if (!key) return;

  const flash = document.createElement('div');
  flash.className = 'flash';
  flash.textContent = messages[key];
  document.body.appendChild(flash);
  setTimeout(() => flash.remove(), 5000);
})();
