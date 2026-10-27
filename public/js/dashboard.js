(async function loadDashboard() {
  const script = document.currentScript;
  const lab = script.dataset.lab;
  const response = await fetch(`/${lab}/api/dashboard`);

  if (!response.ok) {
    window.location.href = `/${lab}/login`;
    return;
  }

  const data = await response.json();
  document.getElementById('welcome').textContent = `Welcome, ${data.user.username}`;
  document.getElementById('profile').textContent = JSON.stringify(data.user, null, 2);

  const comments = document.getElementById('comments');
  comments.innerHTML = '';

  data.comments.forEach((comment) => {
    const item = document.createElement('article');
    item.className = 'comment';

    if (lab === 'vulnerable') {
      // VULNERABLE: innerHTML executes attacker-controlled HTML and scripts.
      item.innerHTML = `<strong>${comment.username}</strong><p>${comment.message}</p><small>${comment.created_at}</small>`;
    } else {
      // SECURE: textContent treats user content as text, so tags do not execute.
      const name = document.createElement('strong');
      const message = document.createElement('p');
      const time = document.createElement('small');
      name.textContent = comment.username;
      message.textContent = comment.message;
      time.textContent = comment.created_at;
      item.append(name, message, time);
    }

    comments.appendChild(item);
  });

  const attempts = document.getElementById('attempts');
  attempts.innerHTML = '';
  data.attempts.forEach((attempt) => {
    const row = document.createElement('div');
    row.className = 'attempt';
    const status = attempt.success ? 'success' : 'fail';

    const name = document.createElement('span');
    const result = document.createElement('span');
    result.className = `status-${status}`;

    if (lab === 'vulnerable') {
      // VULNERABLE: reflected stored login input can be rendered as HTML.
      name.innerHTML = attempt.username;
    } else {
      name.textContent = attempt.username;
    }

    result.textContent = status;
    row.append(name, result);
    attempts.appendChild(row);
  });
})();
