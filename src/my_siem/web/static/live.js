// Swaps in the section fragment, re-fetched every few seconds (see my_siem/web/__init__.py).
// Polled, not streamed: some proxies hold a never-ending response forever.
// Without JavaScript the page still shows the data as of its load.
const panel = document.querySelector("[data-fragment]");
const status = document.getElementById("live-status");
const poll = document.getElementById("poll");
const pollEvery = document.getElementById("poll-every");
const STORE_KEY = "my_siem.poll-every";

let delay = Number(panel?.dataset.every) || 5000;
let timer = null;
let inFlight = false;

function schedule() {
  clearTimeout(timer);
  timer = setTimeout(refresh, delay);
}

// The time window, as the query of every fragment fetch and tab link.
const windowForm = document.getElementById("window");
const windowCount = document.getElementById("window-count");
const windowLabel = document.getElementById("window-label");

function windowQuery() {
  return windowForm ? new URLSearchParams(new FormData(windowForm)).toString() : "";
}

async function refresh() {
  inFlight = true;
  // Dropped if the window changes meanwhile: an older answer must not win.
  const query = windowQuery();
  try {
    const res = await fetch(`${panel.dataset.fragment}?${query}`, { cache: "no-store" });
    // A proxy whose session expired may redirect to its login page; never show that.
    if (!res.ok || res.redirected) throw new Error(`HTTP ${res.status}`);
    const html = await res.text();
    if (query !== windowQuery()) return;
    // A swap would otherwise fold every <details> the reader opened.
    const open = [...panel.querySelectorAll("details[open][id]")].map((d) => d.id);
    // Rendered by the server with autoescaping on; see CSP in my_siem/web/__init__.py.
    panel.innerHTML = html;
    for (const id of open) document.getElementById(id)?.setAttribute("open", "");
    status.textContent = "live";
  } catch {
    status.textContent = "disconnected, retrying…";
  } finally {
    inFlight = false;
  }
  // Scheduled after each answer, so a slow server never gets overlapping requests.
  schedule();
}

// The choice is a per-browser convenience; storage may be blocked, so it is optional.
function savedSeconds() {
  try {
    return localStorage.getItem(STORE_KEY);
  } catch {
    return null;
  }
}

function windowUnit() {
  return windowForm.querySelector("input[name=unit]:checked");
}

function showWindow() {
  const n = Number(windowCount.value);
  windowLabel.textContent = `Last ${n} ${windowUnit().value}${n > 1 ? "s" : ""}`;
}

// The window lives in the URL, so a reload, a bookmark or a tab switch keeps it.
function applyWindow() {
  const query = windowQuery();
  history.replaceState(null, "", `?${query}`);
  for (const tab of document.querySelectorAll(".tabs a")) {
    tab.search = query;
  }
  clearTimeout(timer);
  refresh();
}

if (panel && windowForm) {
  windowForm.addEventListener("submit", (e) => {
    e.preventDefault();
    applyWindow();
  });
  for (const radio of windowForm.querySelectorAll("input[name=unit]")) {
    radio.addEventListener("change", () => {
      windowCount.max = radio.dataset.max;
      windowCount.value = Math.min(Number(windowCount.value), Number(radio.dataset.max));
      showWindow();
      applyWindow();
    });
  }
  // The label follows the thumb; the data waits for it to be let go.
  windowCount.addEventListener("input", showWindow);
  windowCount.addEventListener("change", applyWindow);
}

if (panel) {
  const saved = savedSeconds();
  if (saved && [...pollEvery.options].some((o) => o.value === saved)) {
    pollEvery.value = saved;
    delay = Number(saved) * 1000;
  }
  pollEvery.addEventListener("change", () => {
    delay = Number(pollEvery.value) * 1000;
    try {
      localStorage.setItem(STORE_KEY, pollEvery.value);
    } catch {}
    // A running fetch reschedules itself with the new delay when it ends.
    if (!inFlight) schedule();
  });
  poll.hidden = false;
  status.textContent = "connecting…";
  refresh();
}

// A cookie, not localStorage, so the server renders the choice and nothing flashes.
const themeToggle = document.getElementById("theme-toggle");

function showTheme(theme) {
  themeToggle.textContent = theme === "light" ? "Dark mode" : "Light mode";
}

if (themeToggle) {
  showTheme(document.documentElement.dataset.theme);
  themeToggle.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    document.cookie = `my_siem_theme=${next}; path=/; max-age=31536000; SameSite=Lax`;
    showTheme(next);
  });
  themeToggle.hidden = false;
}
