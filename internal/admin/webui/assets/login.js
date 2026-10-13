// Sign-in form. The CSP keeps form-action 'none', so the submit is taken over
// here and sent with fetch. Every string is set with textContent. The
// password is only ever held in the input and the request body.
(function () {
  "use strict";

  var form = document.getElementById("login-form");
  var input = document.getElementById("password");
  var box = document.getElementById("login-error");
  var text = document.getElementById("login-error-text");
  var submit = document.getElementById("login-submit");

  function fail(msg) {
    text.textContent = msg;
    box.hidden = false;
    input.focus();
    input.select();
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    box.hidden = true;
    submit.disabled = true;
    fetch("/api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: input.value })
    }).then(function (res) {
      if (res.status === 204) {
        input.value = "";
        location.replace("/");
        return;
      }
      if (res.status === 429) {
        fail("Too many failed attempts, try again later");
      } else if (res.status === 401) {
        fail("Invalid password");
      } else {
        fail("Sign-in failed (HTTP " + res.status + ")");
      }
    }).catch(function () {
      fail("Could not reach the server");
    }).then(function () {
      submit.disabled = false;
    });
  });
})();
