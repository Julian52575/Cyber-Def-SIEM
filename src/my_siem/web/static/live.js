// Swaps in each fragment the server pushes over SSE (see my_siem/web/__init__.py).
// Without JavaScript the page still shows the data as of its load.
const panel = document.querySelector("[data-stream]");
const status = document.getElementById("live-status");

if (panel) {
  const source = new EventSource(panel.dataset.stream);
  status.textContent = "connecting…";
  source.addEventListener("open", () => {
    status.textContent = "live";
  });
  source.addEventListener("error", () => {
    status.textContent = "disconnected, retrying…";
  });
  source.addEventListener("update", (event) => {
    // A swap would otherwise fold every <details> the reader opened.
    const open = [...panel.querySelectorAll("details[open][id]")].map((d) => d.id);
    // Rendered by the server with autoescaping on; see CSP in my_siem/web/__init__.py.
    panel.innerHTML = event.data;
    for (const id of open) document.getElementById(id)?.setAttribute("open", "");
    status.textContent = "live";
  });
}
