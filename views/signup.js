function showLogin() {
  document.getElementById('signup-card').style.display = 'none';
  document.getElementById('login-card').style.display = 'block';
}

function showSignup() {
  document.getElementById('login-card').style.display = 'none';
  document.getElementById('signup-card').style.display = 'block';
}

document.getElementById('signup-form').addEventListener('submit', function (event) {
  event.preventDefault();
  
  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirm-password').value;
  const passwordError = document.getElementById('password-error');
  const confirmPasswordError = document.getElementById('confirm-password-error');

  let isValid = true;

  // Check if password is at least 8 characters long
  if (password.length < 8) {
      passwordError.textContent = 'Password must be at least 8 characters long.';
      passwordError.style.display = 'block';
      isValid = false;
  } else {
      passwordError.style.display = 'none';
  }

  // Check if passwords match
  if (password !== confirmPassword) {
      confirmPasswordError.textContent = 'Passwords do not match.';
      confirmPasswordError.style.display = 'block';
      isValid = false;
  } else {
      confirmPasswordError.style.display = 'none';
  }

  if (isValid) {
      alert('Signup successful');
      // Here you can submit the form data to the server
  }
});

document.getElementById('login-form').addEventListener('submit', function (event) {
  event.preventDefault();
  alert('Login successful');
  // Here you can add login functionality
});
