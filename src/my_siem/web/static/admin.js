// The admin tab's log import: estimate, confirm in a dialog, then follow it as it runs.
// Jobs are polled by live.js; this also rescans the log sizes in place.
// Logs and paths are not trusted: everything shown is set as text, never as HTML.
const form = document.getElementById("import-form");
const dialog = document.getElementById("import-confirm");
const estimateButton = document.getElementById("import-estimate");
const message = document.getElementById("import-message");
const goButton = document.getElementById("import-go");
let pending = null; // the import the open dialog asks to confirm

const TZ = "Europe/Paris";

function fmtBytes(n) {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return i === 0 ? `${n} B` : `${n.toFixed(1)} ${units[i]}`;
}

function fmtTime(iso) {
  return new Date(iso).toLocaleString("en-GB", {
    timeZone: TZ,
    weekday: "short",
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function fmtCount(n) {
  return n.toLocaleString("en-US");
}

function row(cells) {
  const tr = document.createElement("tr");
  for (const [text, cls] of cells) {
    const td = document.createElement("td");
    td.textContent = text;
    if (cls) td.className = cls;
    tr.append(td);
  }
  return tr;
}

function item(text, cls) {
  const li = document.createElement("li");
  li.textContent = text;
  if (cls) li.className = cls;
  return li;
}

// FastAPI's errors: a string, or a list of validation failures.
async function failure(res) {
  let detail = res.statusText;
  try {
    const body = await res.json();
    if (typeof body.detail === "string") detail = body.detail;
    if (Array.isArray(body.detail)) detail = body.detail.map((d) => d.msg).join("; ");
  } catch {}
  // The status and URL tell a refusal by my_siem from one by a proxy on the way.
  return `${detail} (HTTP ${res.status} from ${new URL(res.url).pathname})`;
}

function chosen() {
  return {
    commands: [...form.querySelectorAll("input[name=command]:checked")].map((i) => i.value),
    unit: form.querySelector("input[name=unit]:checked").value,
    count: Number(form.elements.count.value),
  };
}

function showEstimate(job) {
  document.getElementById("import-confirm-span").textContent =
    `From ${fmtTime(job.since)} to ${fmtTime(job.until)}, Paris time.`;
  const rows = document.getElementById("import-confirm-rows");
  const warnings = document.getElementById("import-confirm-warnings");
  rows.replaceChildren();
  warnings.replaceChildren();
  let fresh = 0;
  for (const r of job.reports) {
    const after = r.folder_bytes + r.gz_bytes;
    fresh += r.error ? 0 : r.new;
    rows.append(
      row([
        [r.command],
        [r.where, "wrap"],
        [fmtCount(r.events), "num"],
        [fmtCount(r.new), "num"],
        [`${fmtBytes(r.gz_bytes)} (${fmtBytes(r.raw_bytes)} unzipped)`, "num"],
        [r.cap_bytes ? `${fmtBytes(after)} of ${fmtBytes(r.cap_bytes)}` : fmtBytes(after), "num"],
      ]),
    );
    if (r.error) warnings.append(item(`${r.command}: cannot read the source: ${r.error}`, "error"));
    if (r.skipped_hours) {
      warnings.append(
        item(`${r.command}: ${r.skipped_hours} hour(s) skipped: the running command already logged them.`),
      );
    }
    if (r.cap_bytes && after > r.cap_bytes) {
      warnings.append(
        item(
          `${r.command}: past the size cap. The next sweep deletes the oldest hours, imported ones included.`,
          "error",
        ),
      );
    }
  }
  if (fresh === 0) warnings.append(item("Nothing new to import."));
  goButton.disabled = fresh === 0;
  dialog.showModal();
}

async function estimate(event) {
  event.preventDefault();
  if (!form.reportValidity()) return;
  const request = chosen();
  if (request.commands.length === 0) {
    message.textContent = "Pick at least one command.";
    return;
  }
  const query = new URLSearchParams({ unit: request.unit, count: request.count });
  for (const c of request.commands) query.append("command", c);
  estimateButton.disabled = true;
  message.textContent = "Reading the logs to estimate…";
  try {
    const res = await fetch(`${form.dataset.estimate}?${query}`, { cache: "no-store" });
    if (!res.ok) throw new Error(await failure(res));
    pending = request;
    message.textContent = "";
    showEstimate(await res.json());
  } catch (err) {
    message.textContent = `Estimate failed: ${err.message}`;
  } finally {
    estimateButton.disabled = false;
  }
}

async function start() {
  goButton.disabled = true;
  try {
    // JSON, which a form on another site cannot send: see _cross_site in api.py.
    let res = await fetch(form.dataset.start, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(pending),
    });
    // HACK(import): a proxy that forwards GET only answered 405 (my_siem never does).
    // Goes with /admin/import/start in api.py.
    if (res.status === 405) {
      const query = new URLSearchParams({
        unit: pending.unit,
        count: pending.count,
        token: form.dataset.token,
      });
      for (const c of pending.commands) query.append("command", c);
      res = await fetch(`${form.dataset.startGet}?${query}`, { cache: "no-store" });
    }
    if (!res.ok) throw new Error(await failure(res));
    dialog.close();
    showProgress(await res.json());
    follow();
  } catch (err) {
    document
      .getElementById("import-confirm-warnings")
      .append(item(`Import refused: ${err.message}`, "error"));
  }
}

const TITLES = {
  running: "Importing…",
  done: "Last import done",
  failed: "Last import finished with errors",
};

function showProgress(job) {
  const box = document.getElementById("import-progress");
  document.getElementById("import-progress-title").textContent =
    `${TITLES[job.state]} (started ${fmtTime(job.started_at)}; ` +
    `${fmtTime(job.since)} to ${fmtTime(job.until)})`;
  const rows = document.getElementById("import-progress-rows");
  rows.replaceChildren(
    ...job.reports.map((r) =>
      row([
        [r.command],
        [r.where, "wrap"],
        [fmtCount(r.events), "num"],
        [fmtCount(r.new), "num"],
        [fmtCount(r.hours), "num"],
        [fmtBytes(r.gz_bytes), "num"],
        r.error ? [r.error, "error"] : [job.state === "running" ? "…" : "done"],
      ]),
    ),
  );
  box.hidden = false;
  estimateButton.disabled = job.state === "running";
}

async function follow() {
  try {
    const res = await fetch(form.dataset.status, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const job = await res.json();
    if (job.state === "idle") return;
    showProgress(job);
    if (job.state === "running") {
      setTimeout(follow, 1000);
    } else {
      rescanUsage();
    }
  } catch {
    setTimeout(follow, 5000);
  }
}

async function rescanUsage() {
  const card = document.getElementById("usage");
  const link = document.getElementById("usage-rescan");
  if (!card || !link) return;
  try {
    const res = await fetch(`${link.dataset.usage}${location.search}`, { cache: "no-store" });
    if (!res.ok || res.redirected) throw new Error(`HTTP ${res.status}`);
    // Rendered by the server with autoescaping on, like live.js's fragments.
    card.outerHTML = await res.text();
  } catch {
    link.textContent = "Rescan (failed, retry)";
  }
}

// The card is swapped whole, link included, so listen above it.
document.addEventListener("click", (event) => {
  if (event.target.closest("#usage-rescan")) {
    event.preventDefault();
    rescanUsage();
  }
});

if (form) {
  const count = form.elements.count;
  for (const radio of form.querySelectorAll("input[name=unit]")) {
    radio.addEventListener("change", () => {
      count.max = radio.dataset.max;
      if (Number(count.value) > Number(count.max)) count.value = count.max;
    });
  }
  form.addEventListener("submit", estimate);
  goButton.addEventListener("click", start);
  document.getElementById("import-cancel").addEventListener("click", () => dialog.close());
  // Shows the last import, and keeps following one already running.
  follow();
}
