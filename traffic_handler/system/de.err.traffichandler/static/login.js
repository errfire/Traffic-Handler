document.addEventListener('DOMContentLoaded', function () {
      const oauthButton = document.getElementById('oauth-button');
      const loginForm = document.querySelector('.login-form');

      oauthButton.addEventListener('click', function () {
        window.location.href = '/rest/v1/auth/oauth';
      });
    });
    document.addEventListener('DOMContentLoaded', function () {
  const oauthButton = document.getElementById('oauth-button');
  const loginForm = document.querySelector('.login-form');
  const loadingOverlay = document.getElementById('loading-overlay');

  loginForm.addEventListener('submit', function () {
    loadingOverlay.style.display = 'flex';
  });

  oauthButton.addEventListener('click', function () {
    window.location.href = '/rest/v1/auth/oauth';
  });
});