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
const windowSlider = document.getElementById("window-slider");
const windowUnitLabel = document.getElementById("window-unit");
const TYPING_PAUSE = 600;
let typingTimer = null;

// Mid-typing the field may be empty or out of range: polls keep the last valid count.
function windowQuery() {
  if (!windowForm) return "";
  const count = typedCount() ?? windowSlider.value;
  return new URLSearchParams({ unit: windowUnit().value, count }).toString();
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
  windowUnitLabel.textContent = `${windowUnit().value}${n > 1 ? "s" : ""}`;
}

// A whole number within the unit's range, or null while it is not one (e.g. empty).
function typedCount() {
  const n = Number(windowCount.value);
  return windowCount.value !== "" && Number.isInteger(n) && n >= 1 && n <= Number(windowCount.max)
    ? n
    : null;
}

function setCount(n) {
  windowCount.value = n;
  windowSlider.value = n;
  showWindow();
}

// The window lives in the URL, so a reload, a bookmark or a tab switch keeps it.
function applyWindow() {
  clearTimeout(typingTimer);
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
      const max = Number(radio.dataset.max);
      windowCount.max = max;
      windowSlider.max = max;
      setCount(Math.min(typedCount() ?? Number(windowSlider.value), max));
      applyWindow();
    });
  }
  // The number follows the thumb; the data waits for it to be let go.
  windowSlider.addEventListener("input", () => setCount(windowSlider.value));
  windowSlider.addEventListener("change", applyWindow);
  // Typed: applied after a pause, so "45" does not first load "4".
  windowCount.addEventListener("input", () => {
    clearTimeout(typingTimer);
    const n = typedCount();
    if (n === null) return;
    windowSlider.value = n;
    showWindow();
    typingTimer = setTimeout(applyWindow, TYPING_PAUSE);
  });
  // On leaving the field (or Enter), an out-of-range value is pulled back in.
  windowCount.addEventListener("change", () => {
    const n = Number(windowCount.value);
    const valid = windowCount.value !== "" && Number.isFinite(n);
    const max = Number(windowCount.max);
    setCount(valid ? Math.min(Math.max(Math.round(n), 1), max) : windowSlider.value);
    applyWindow();
  });
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
