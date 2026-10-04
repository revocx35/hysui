"use strict";

document.getElementById("login").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = document.getElementById("error");
  const btn = ev.target.querySelector("button");
  err.textContent = "";
  btn.disabled = true;
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Hysui": "1" },
      body: JSON.stringify({
        username: document.getElementById("username").value.trim(),
        password: document.getElementById("password").value,
      }),
    });
    if (res.ok) {
      location.href = "/";
      return;
    }
    const body = await res.json().catch(() => ({}));
    err.textContent = body.error || `Sign-in failed (${res.status})`;
  } catch (e) {
    err.textContent = "Cannot reach the server.";
  } finally {
    btn.disabled = false;
  }
});
