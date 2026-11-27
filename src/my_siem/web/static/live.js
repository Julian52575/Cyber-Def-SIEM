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

async function refresh() {
  inFlight = true;
  try {
    const res = await fetch(panel.dataset.fragment, { cache: "no-store" });
    // A proxy whose session expired may redirect to its login page; never show that.
    if (!res.ok || res.redirected) throw new Error(`HTTP ${res.status}`);
    const html = await res.text();
    // A swap would otherwise fold every <details> the reader opened.
    const open = [...panel.querySelectorAll("details[open][id]")].map((d) => d.id);
    // Rendered by the server with autoescaping on; see CSP in my_siem/web/__init__.py.
    panel.innerHTML = html;
    for (const id of open) document.getElementById(id)?.setAttribute("open", "");
    status.textContent = "live";
  } catch {
    status.textContent = "disconnected, retrying…";
  }
  inFlight = false;
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
