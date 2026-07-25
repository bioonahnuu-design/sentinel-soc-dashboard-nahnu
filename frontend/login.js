const form = document.querySelector('#login-form');
const submit = document.querySelector('#login-submit');
const errorBox = document.querySelector('#login-error');
const password = document.querySelector('#password');

document.querySelector('#toggle-password').addEventListener('click', (event) => {
  const visible = password.type === 'text';
  password.type = visible ? 'password' : 'text';
  event.currentTarget.textContent = visible ? 'Show' : 'Hide';
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  submit.disabled = true;
  submit.textContent = 'Verifying...';
  try {
    const response = await fetch('/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: document.querySelector('#username').value.trim(),
        password: password.value,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Sign in failed');
    window.location.replace('/');
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.hidden = false;
    submit.disabled = false;
    submit.textContent = 'Sign in securely';
  }
});
