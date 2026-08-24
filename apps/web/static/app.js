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
  const latestThread = document.querySelector(".ask-thread[data-scroll-latest]");
  if (latestThread) {
    window.requestAnimationFrame(() => {
      latestThread.scrollTop = latestThread.scrollHeight;
    });
  }
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

  const settingsForm = document.querySelector("#model-settings-form");
  const probeButton = document.querySelector("#probe-model");
  const sendSettingsRequest = async (url, body) => {
    const response = await fetch(url, {
      method: "POST",
      headers: {"X-PodPilot-CSRF": csrf, "Content-Type": "application/x-www-form-urlencoded"},
      credentials: "same-origin",
      body,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || "The model settings request failed.");
    return payload;
  };
  if (settingsForm?.dataset.saveUrl) {
    settingsForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = settingsForm.querySelector('button[type="submit"]');
      if (submit) { submit.disabled = true; submit.textContent = "Saving…"; }
      try {
        await sendSettingsRequest(settingsForm.dataset.saveUrl, new URLSearchParams(new FormData(settingsForm)));
        window.location.reload();
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        if (submit) { submit.disabled = false; submit.textContent = "Save profile"; }
      }
    });
  }
  if (probeButton?.dataset.probeUrl) {
    probeButton.addEventListener("click", async () => {
      probeButton.disabled = true;
      probeButton.textContent = "Testing…";
      try {
        await sendSettingsRequest(probeButton.dataset.probeUrl, "");
        window.location.reload();
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        probeButton.disabled = false;
        probeButton.textContent = "Test connection";
      }
    });
  }

  document.querySelectorAll(".review-action").forEach((button) => {
    button.addEventListener("click", () => {
      const target = document.querySelector(`#${CSS.escape(button.dataset.reviewTarget || "")}`);
      if (target) {
        target.hidden = !target.hidden;
        button.textContent = target.hidden ? "Review approval" : "Hide approval";
      }
    });
  });
  document.querySelectorAll(".approve-action").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!csrf || !button.dataset.actionUrl) return;
      button.disabled = true;
      button.textContent = "Executing and verifying…";
      try {
        const response = await fetch(button.dataset.actionUrl, {
          method: "POST",
          headers: {"X-PodPilot-CSRF": csrf},
          credentials: "same-origin",
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.detail || "The remediation could not be executed.");
        }
        window.location.assign(response.url);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        button.disabled = false;
        button.textContent = "Approve and run";
      }
    });
  });
  document.querySelectorAll(".cancel-action").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!csrf || !button.dataset.actionUrl) return;
      button.disabled = true;
      button.textContent = "Cancelling…";
      try {
        const response = await fetch(button.dataset.actionUrl, {
          method: "POST",
          headers: {"X-PodPilot-CSRF": csrf},
          credentials: "same-origin",
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.detail || "The remediation preview could not be cancelled.");
        }
        window.location.assign(response.url);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        button.disabled = false;
        button.textContent = "Cancel preview";
      }
    });
  });
  document.querySelectorAll(".run-checks-action").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!csrf || !button.dataset.actionUrl) return;
      button.disabled = true;
      button.textContent = "Investigating…";
      try {
        const response = await fetch(button.dataset.actionUrl, {
          method: "POST",
          headers: {"X-PodPilot-CSRF": csrf},
          credentials: "same-origin",
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.detail || "The diagnostic checks could not be completed.");
        }
        window.location.assign(response.url);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        button.disabled = false;
        button.textContent = "Run safe checks";
      }
    });
  });
  const chatForm = document.querySelector("#investigation-chat-form");
  if (chatForm?.dataset.chatUrl) {
    chatForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!csrf) return;
      const submit = chatForm.querySelector('button[type="submit"]');
      if (submit) { submit.disabled = true; submit.textContent = "Thinking…"; }
      try {
        const response = await fetch(chatForm.dataset.chatUrl, {
          method: "POST",
          headers: {
            "X-PodPilot-CSRF": csrf,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          credentials: "same-origin",
          body: new URLSearchParams(new FormData(chatForm)),
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.detail || "PodPilot could not answer this question.");
        }
        window.location.assign(response.url);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        if (submit) { submit.disabled = false; submit.textContent = "Ask PodPilot"; }
      }
    });
  }
  const adhocForm = document.querySelector(".adhoc-chat-form");
  if (adhocForm?.dataset.chatUrl) {
    adhocForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!csrf) return;
      const submit = adhocForm.querySelector('button[type="submit"]');
      if (submit) { submit.disabled = true; submit.textContent = "Investigating…"; }
      try {
        const response = await fetch(adhocForm.dataset.chatUrl, {
          method: "POST",
          headers: {"X-PodPilot-CSRF": csrf, "Content-Type": "application/x-www-form-urlencoded"},
          credentials: "same-origin",
          body: new URLSearchParams(new FormData(adhocForm)),
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.detail || "PodPilot could not investigate this question.");
        }
        window.location.assign(response.url);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        if (submit) { submit.disabled = false; submit.textContent = "Investigate"; }
      }
    });
    const textarea = adhocForm.querySelector("textarea");
    textarea?.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
        event.preventDefault();
        if (adhocForm.checkValidity()) adhocForm.requestSubmit();
      }
    });
  }
  document.querySelectorAll('.chat-citations a[href^="#evidence-"]').forEach((link) => {
    link.addEventListener("click", (event) => {
      const target = document.getElementById(link.hash.slice(1));
      if (!target) return;
      event.preventDefault();
      document.querySelectorAll(".evidence-focus").forEach((item) => item.classList.remove("evidence-focus"));
      target.classList.add("evidence-focus");
      target.scrollIntoView({behavior: "smooth", block: "center"});
      target.focus({preventScroll: true});
      window.history.replaceState(null, "", link.hash);
    });
  });
  document.querySelectorAll(".delete-chat-form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!csrf || !form.dataset.deleteUrl) return;
      if (!window.confirm("Delete this conversation and its collected evidence? This cannot be undone.")) return;
      const button = form.querySelector('button[type="submit"]');
      if (button) { button.disabled = true; button.textContent = "Deleting…"; }
      try {
        const response = await fetch(form.dataset.deleteUrl, {
          method: "POST", headers: {"X-PodPilot-CSRF": csrf}, credentials: "same-origin",
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.detail || "The conversation could not be deleted.");
        }
        window.location.assign(response.url);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        if (button) { button.disabled = false; button.textContent = "Delete conversation"; }
      }
    });
  });
})();
