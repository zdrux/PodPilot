document.addEventListener("toggle", async (event) => {
  const details = event.target;
  if (!(details instanceof HTMLDetailsElement) || !details.open ||
      !details.dataset.logEvidenceUrl || details.dataset.loaded) return;
  const output = details.querySelector("[data-log-excerpt]");
  details.dataset.loaded = "loading";
  output.textContent = "Loading retained logs…";
  try {
    const response = await fetch(details.dataset.logEvidenceUrl, {cache: "no-store"});
    const data = await response.json();
    output.textContent = response.ok ? (data.excerpt || "No log lines were collected.") :
      (data.detail || "Log evidence is unavailable.");
    details.dataset.loaded = "yes";
  } catch {
    output.textContent = "Could not load logs. Close and reopen to retry.";
    delete details.dataset.loaded;
  }
}, true);
