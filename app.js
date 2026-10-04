
// Surface runtime errors instead of leaving the page appearing unresponsive.
window.addEventListener("error", event => {
  console.error("Security demo runtime error:", event.error || event.message);
  const existing = document.getElementById("runtime-error-notice");
  if (existing) return;
  const notice = document.createElement("div");
  notice.id = "runtime-error-notice";
  notice.setAttribute("role", "alert");
  notice.style.cssText = "position:fixed;left:12px;right:12px;bottom:12px;z-index:99999;padding:12px 16px;background:#3b1111;color:#fff;border:1px solid #ef4444;font:12px/1.5 monospace;";
  notice.textContent = "A JavaScript error interrupted this demo. Open your browser Developer Tools (F12) → Console for details, then refresh the page.";
  document.body.appendChild(notice);
});

/*
 * Static-site teaching demo for Netlify.
 * Data: localStorage (browser-local, not shared between devices).
 * Security note: client-side authentication, roles, and lockout are bypassable.
 * Do not use real credentials or present this as production security.
 */
const DB = { users: "ias2_users_v2", logs: "ias2_events_v2", attempts: "ias2_attempts_v2" };
const MAX_ATTEMPTS = 5;
const LOCKOUT_SECONDS = 30;
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,32}$/;
const SQL_META_RE = /(?:--|\/\*|\*\/|;|'|"|`|\\|\b(?:OR|AND)\b\s+\S+\s*(?:=|LIKE|IS)\s*|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bSLEEP\b|\bBENCHMARK\b)/i;

function getJSON(key, fallback) {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(key));
    return parsed ?? fallback;
  } catch (error) {
    console.warn(`Local demo storage could not read ${key}; using an empty default.`, error);
    return fallback;
  }
}
function putJSON(key, value) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch (error) {
    console.error(`Local demo storage could not save ${key}.`, error);
    return false;
  }
}
function getUsers() {
  const users = getJSON(DB.users, []);
  return Array.isArray(users) ? users.filter(user => user && typeof user.username === "string") : [];
}
function getLogs() {
  const logs = getJSON(DB.logs, []);
  return Array.isArray(logs) ? logs.filter(item => item && typeof item === "object") : [];
}
function logEvent(username, type, success, details) {
  const logs = getLogs();
  logs.unshift({ timestamp: new Date().toISOString(), username: String(username || "anonymous").slice(0, 100), type, success: !!success, details: String(details || "").slice(0, 180) });
  putJSON(DB.logs, logs.slice(0, 300));
}
function message(element, text, kind = "error") {
  if (!element) return;
  element.textContent = text;
  element.className = "message show" + (kind === "success" ? " success" : "");
}
function initializeDemoAdmin() {
  const users = getUsers();
  if (!users.some(user => user.username.toLowerCase() === "admin")) {
    users.push({ username: "admin", password: "AdminDemo123!", privilege: "admin", createdAt: new Date().toISOString() });
    putJSON(DB.users, users);
  }
}
function attemptMap() {
  const attempts = getJSON(DB.attempts, {});
  return attempts && typeof attempts === "object" && !Array.isArray(attempts) ? attempts : {};
}
function attemptState(username) { return attemptMap()[username.toLowerCase()] || { count: 0, lockedUntil: 0 }; }
function saveAttemptState(username, state) {
  const all = attemptMap(); all[username.toLowerCase()] = state; putJSON(DB.attempts, all);
}
function suspiciousInput(value) { return SQL_META_RE.test(value); }

function initLogin() {
  const form = document.getElementById("login-form");
  if (!form) return;
  initializeDemoAdmin();
  const userEl = document.getElementById("username");
  const passEl = document.getElementById("password");
  const msg = document.getElementById("login-message");
  const attemptsMsg = document.getElementById("attempts-message");
  const lockBox = document.getElementById("lockout-box");
  const button = document.getElementById("login-btn");
  let countdown = null;

  function startCountdown(until, username) {
    if (countdown) clearInterval(countdown);
    button.disabled = true;
    lockBox.classList.add("show");
    function tick() {
      const left = Math.max(0, Math.ceil((until - Date.now()) / 1000));
      lockBox.textContent = `Account temporarily locked. Try again in ${left} second${left === 1 ? "" : "s"}.`;
      if (left <= 0) {
        clearInterval(countdown); countdown = null;
        lockBox.classList.remove("show"); button.disabled = false;
        saveAttemptState(username, { count: 0, lockedUntil: 0 });
        attemptsMsg.textContent = "Lockout ended. You may try again.";
      }
    }
    tick(); countdown = setInterval(tick, 250);
  }

  form.addEventListener("submit", event => {
    event.preventDefault();
    const username = userEl.value.trim();
    const password = passEl.value;
    msg.className = "message"; attemptsMsg.textContent = "";
    if (!username || !password) return message(msg, "Enter both username and password.");
    if (username.length > 32 || password.length > 128) {
      logEvent(username, "input_validation", false, "Input exceeded allowed length");
      return message(msg, "Input is too long.");
    }
    if (!USERNAME_RE.test(username)) {
      logEvent(username, "input_validation", false, "Username failed format validation");
      return message(msg, "Invalid username format. Use 3–32 letters, numbers, dots, underscores, or hyphens.");
    }
    if (suspiciousInput(username)) {
      logEvent(username, "sql_injection_blocked", false, "SQL-like characters or keywords detected in username");
      return message(msg, "Input rejected by validation. Special characters or SQL-like patterns are not allowed in usernames.");
    }
    const state = attemptState(username);
    if (state.lockedUntil > Date.now()) {
      startCountdown(state.lockedUntil, username);
      return;
    }
    if (state.lockedUntil && state.lockedUntil <= Date.now()) saveAttemptState(username, { count: 0, lockedUntil: 0 });

    const user = getUsers().find(item => item.username.toLowerCase() === username.toLowerCase() && item.password === password);
    if (user) {
      saveAttemptState(username, { count: 0, lockedUntil: 0 });
      logEvent(username, "authentication", true, "Valid demo credentials");
      const token = (window.crypto && typeof window.crypto.randomUUID === "function"
        ? window.crypto.randomUUID()
        : `${Date.now()}-${Math.random()}-${Math.random()}`).replace(/-/g, "");
      sessionStorage.setItem("auth_token", token);
      sessionStorage.setItem("auth_user", user.username);
      sessionStorage.setItem("auth_privilege", user.privilege === "admin" ? "admin" : "user");
      window.location.href = user.privilege === "admin" ? "admin.html" : "home.html";
      return;
    }
    const next = { count: state.count + 1, lockedUntil: 0 };
    logEvent(username, "authentication", false, "Invalid credentials");
    if (next.count >= MAX_ATTEMPTS) {
      next.lockedUntil = Date.now() + LOCKOUT_SECONDS * 1000;
      saveAttemptState(username, next);
      message(msg, "Too many unsuccessful attempts.");
      attemptsMsg.textContent = "0 attempts remaining";
      startCountdown(next.lockedUntil, username);
    } else {
      saveAttemptState(username, next);
      const remaining = MAX_ATTEMPTS - next.count;
      message(msg, "Invalid username or password.");
      attemptsMsg.textContent = `${remaining} attempt${remaining === 1 ? "" : "s"} remaining before temporary lockout.`;
      attemptsMsg.style.color = remaining <= 2 ? "#f87171" : "#777";
    }
  });
}

function initRegister() {
  const form = document.getElementById("register-form");
  if (!form) return;
  initializeDemoAdmin();
  form.addEventListener("submit", event => {
    event.preventDefault();
    const username = document.getElementById("new-username").value.trim();
    const password = document.getElementById("new-password").value;
    const confirm = document.getElementById("confirm-password").value;
    const msg = document.getElementById("register-message");
    if (!USERNAME_RE.test(username)) return message(msg, "Username must be 3–32 characters and may contain only letters, numbers, dots, underscores, or hyphens.");
    if (password.length < 8 || password.length > 128) return message(msg, "Password must be between 8 and 128 characters.");
    if (password !== confirm) return message(msg, "Passwords do not match.");
    const users = getUsers();
    if (users.some(user => user.username.toLowerCase() === username.toLowerCase())) return message(msg, "That username is already registered.");
    // Privilege is assigned here, never accepted from a form field.
    users.push({ username, password, privilege: "user", createdAt: new Date().toISOString() });
    putJSON(DB.users, users);
    logEvent(username, "registration", true, "Standard user account created");
    form.reset();
    message(msg, "Account created. You can now sign in.", "success");
  });
}

function requireRole(requiredRole) {
  const token = sessionStorage.getItem("auth_token");
  const username = sessionStorage.getItem("auth_user");
  const privilege = sessionStorage.getItem("auth_privilege");
  if (!token || !username) { window.location.replace("index.html"); return null; }
  if (requiredRole && privilege !== requiredRole) {
    window.location.replace(privilege === "admin" ? "admin.html" : "home.html");
    return null;
  }
  return { token, username, privilege };
}
function logout() {
  const username = sessionStorage.getItem("auth_user") || "anonymous";
  logEvent(username, "logout", true, "User signed out");
  ["auth_token", "auth_user", "auth_privilege"].forEach(key => sessionStorage.removeItem(key));
  window.location.href = "index.html";
}
document.querySelectorAll("[data-logout]").forEach(button => button.addEventListener("click", logout));

function initHome() {
  const user = requireRole("user");
  if (!user) return;
  ["user-display", "hero-user", "session-user"].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = user.username; });
  const session = document.getElementById("session-id");
  if (session) session.textContent = user.token.slice(-8).toUpperCase();
  const clock = document.getElementById("clock");
  const update = () => { if (clock) clock.textContent = new Date().toLocaleTimeString("en-US", {hour12:false}); };
  update(); setInterval(update, 1000);
}
function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" })[char]);
}
function initAdmin() {
  if (!document.body.classList.contains("admin-page")) return;
  const user = requireRole("admin");
  if (!user) return;
  const tbody = document.getElementById("logs-body");
  const empty = document.getElementById("empty-logs");

  function refresh() {
    const logs = getLogs();
    let failed = 0, successful = 0, sql = 0, enumeration = 0;
    logs.forEach(item => {
      if (item.success) successful++; else failed++;
      if (item.type === "sql_injection_blocked") sql++;
      if (item.type === "user_enumeration") enumeration++;
    });
    document.getElementById("failed-count").textContent = failed;
    document.getElementById("success-count").textContent = successful;
    document.getElementById("sqli-count").textContent = sql;
    document.getElementById("enum-count").textContent = enumeration;
    tbody.innerHTML = logs.map(item => `<tr><td>${escapeHTML(new Date(item.timestamp).toLocaleString())}</td><td>${escapeHTML(item.username)}</td><td class="event-type">${escapeHTML(item.type.toUpperCase())}</td><td><span class="badge ${item.success ? "success" : "danger"}">${item.success ? "Success" : "Blocked/Failed"}</span></td><td>${escapeHTML(item.details || "-")}</td></tr>`).join("");
    empty.style.display = logs.length ? "none" : "block";
  }

  document.getElementById("refresh-btn").addEventListener("click", refresh);
  document.getElementById("search-form").addEventListener("submit", event => {
    event.preventDefault();
    const input = document.getElementById("search-input");
    const query = input.value.trim();
    const output = document.getElementById("search-results");
    if (!query) { output.innerHTML = '<div class="search-result danger">Enter a value to test.</div>'; return; }
    if (query.length > 100) { logEvent(user.username, "input_validation", false, "Search exceeded maximum length"); output.innerHTML = '<div class="search-result danger">Input too long. Limit: 100 characters.</div>'; refresh(); return; }

    const sqlLike = suspiciousInput(query);
    if (sqlLike) {
      logEvent(user.username, "sql_injection_blocked", false, query);
      output.innerHTML = '<div class="search-result danger">BLOCKED: suspicious SQL-like syntax detected. No query was executed.</div>';
    } else {
      logEvent(user.username, "user_enumeration", true, query);
      const normalized = query.toLowerCase();
      const results = getUsers().filter(account => account.username.toLowerCase().includes(normalized) || account.privilege === normalized);
      output.innerHTML = results.length
        ? results.map(account => `<div class="search-result success">USER: <strong>${escapeHTML(account.username)}</strong> <span>[${escapeHTML(account.privilege.toUpperCase())}]</span></div>`).join("")
        : '<div class="search-result">No matching demo accounts.</div>';
    }
    refresh();
  });
  refresh(); setInterval(refresh, 5000);
}
document.addEventListener("DOMContentLoaded", () => { initLogin(); initRegister(); initHome(); initAdmin(); });
