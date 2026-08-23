(() => {
  const renderTime = document.querySelector("#render-time");
  if (renderTime) {
    const parsed = new Date(renderTime.dateTime);
    if (!Number.isNaN(parsed.valueOf())) {
      renderTime.textContent = new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
        timeZone: "UTC",
      }).format(parsed) + " UTC";
    }
  }

  const csrf = document.querySelector('meta[name="podpilot-csrf"]')?.content;
  const toast = document.querySelector("#action-toast");
  document.querySelectorAll(".analyze-button").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!csrf || !button.dataset.analyzeUrl) return;
      button.disabled = true;
      button.textContent = "Analyzing…";
      try {
        const response = await fetch(button.dataset.analyzeUrl, {
          method: "POST",
          headers: {"X-PodPilot-CSRF": csrf},
          credentials: "same-origin",
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.detail || "The investigation could not be created.");
        }
        window.location.assign(response.url);
      } catch (error) {
        if (toast) {
          toast.textContent = error.message;
          toast.hidden = false;
        }
        button.disabled = false;
        button.textContent = "Analyze";
      }
    });
  });
})();
