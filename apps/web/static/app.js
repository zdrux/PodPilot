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
  const pendingNotice = window.sessionStorage.getItem("podpilot-action-notice");
  if (pendingNotice && toast) {
    window.sessionStorage.removeItem("podpilot-action-notice");
    try {
      const notice = JSON.parse(pendingNotice);
      toast.textContent = notice.message;
      toast.classList.toggle("success", notice.tone === "success");
      toast.classList.toggle("warning", notice.tone === "warning");
      toast.hidden = false;
    } catch (_error) {
      window.sessionStorage.removeItem("podpilot-action-notice");
    }
  }
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
        const payload = await sendSettingsRequest(settingsForm.dataset.saveUrl, new URLSearchParams(new FormData(settingsForm)));
        window.location.assign(`/settings/model?edit=${encodeURIComponent(payload.profile_id)}`);
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
        const payload = await sendSettingsRequest(probeButton.dataset.probeUrl, "");
        const notice = payload.status === "ready"
          ? {tone: "success", message: "Connection test passed. This model is ready for PodPilot workflows."}
          : payload.status === "reduced_capability"
            ? {tone: "warning", message: payload.detail || "The endpoint was reached, but a required capability check failed."}
            : {tone: "error", message: payload.detail || "The model endpoint is unavailable."};
        window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify(notice));
        window.location.reload();
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        probeButton.disabled = false;
        probeButton.textContent = "Test connection";
      }
    });
  }
  document.querySelectorAll(".model-action").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!csrf || !button.dataset.actionUrl) return;
      if (button.dataset.confirm && !window.confirm(button.dataset.confirm)) return;
      button.disabled = true;
      try {
        const payload = await sendSettingsRequest(button.dataset.actionUrl, "");
        if (button.dataset.actionKind === "delete") {
          const message = Object.prototype.hasOwnProperty.call(payload, "activated_profile_id")
            ? payload.activated_profile_id
              ? "Model deleted. Another ready model was activated automatically."
              : "Model deleted. PodPilot will run without AI until a model is configured and activated."
            : "Model deleted.";
          window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify({tone: "success", message}));
        }
        window.location.assign("/settings/model");
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        button.disabled = false;
      }
    });
  });

  const knowledgeForm = document.querySelector("#knowledge-form");
  if (knowledgeForm?.dataset.saveUrl) {
    const knowledgeClusterIds = knowledgeForm.querySelector("[data-knowledge-cluster-ids]");
    const knowledgeClusterBoxes = Array.from(knowledgeForm.querySelectorAll("[data-knowledge-cluster]"));
    const syncKnowledgeClusters = () => {
      if (knowledgeClusterIds) {
        knowledgeClusterIds.value = JSON.stringify(
          knowledgeClusterBoxes.filter((item) => item.checked).map((item) => item.value),
        );
      }
    };
    knowledgeClusterBoxes.forEach((item) => item.addEventListener("change", syncKnowledgeClusters));
    syncKnowledgeClusters();
    knowledgeForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = knowledgeForm.querySelector('button[type="submit"]');
      if (submit) { submit.disabled = true; submit.textContent = "Saving…"; }
      try {
        const payload = await sendSettingsRequest(
          knowledgeForm.dataset.saveUrl,
          new URLSearchParams(new FormData(knowledgeForm)),
        );
        window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify({
          tone: "success",
          message: `Knowledge saved as version ${payload.version}.`,
        }));
        window.location.assign(`/memory?edit=${encodeURIComponent(payload.document_id)}`);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        if (submit) { submit.disabled = false; submit.textContent = "Save knowledge"; }
      }
    });
  }
  document.querySelectorAll(".knowledge-status").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!button.dataset.statusUrl) return;
      button.disabled = true;
      try {
        const payload = await sendSettingsRequest(
          button.dataset.statusUrl,
          new URLSearchParams({enabled: button.dataset.enabled || "false"}),
        );
        window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify({
          tone: "success",
          message: `Knowledge entry ${payload.status}.`,
        }));
        window.location.reload();
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        button.disabled = false;
      }
    });
  });

  const clusterSettingsForm = document.querySelector("#cluster-settings-form");
  if (clusterSettingsForm?.dataset.saveUrl) {
    const verifyCheckbox = clusterSettingsForm.querySelector('[name="tls_verify_checkbox"]');
    const verifyValue = clusterSettingsForm.querySelector('[name="tls_verify"]');
    verifyCheckbox?.addEventListener("change", () => {
      if (verifyValue) verifyValue.value = verifyCheckbox.checked ? "true" : "false";
    });
    clusterSettingsForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = clusterSettingsForm.querySelector('button[type="submit"]');
      if (submit) { submit.disabled = true; submit.textContent = "Saving…"; }
      try {
        const payload = await sendSettingsRequest(
          clusterSettingsForm.dataset.saveUrl,
          new URLSearchParams(new FormData(clusterSettingsForm)),
        );
        window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify({
          tone: "success", message: "Cluster connection saved. Test it before using it for Ask PodPilot.",
        }));
        window.location.assign(`/settings/clusters?edit=${encodeURIComponent(payload.cluster_id)}`);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        if (submit) { submit.disabled = false; submit.textContent = "Save cluster"; }
      }
    });
  }
  document.querySelectorAll(".cluster-action").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!button.dataset.actionUrl) return;
      if (button.dataset.confirm && !window.confirm(button.dataset.confirm)) return;
      button.disabled = true;
      const prior = button.textContent;
      button.textContent = button.dataset.actionKind === "test" ? "Testing…" : "Disabling…";
      try {
        const payload = await sendSettingsRequest(button.dataset.actionUrl, "");
        const passed = payload.status === "ready";
        window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify({
          tone: passed ? "success" : payload.status === "disabled" ? "success" : "error",
          message: payload.detail || (payload.status === "disabled" ? "Cluster disabled and token removed." : "Cluster connection tested."),
        }));
        window.location.reload();
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        button.disabled = false;
        button.textContent = prior;
      }
    });
  });

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
  const clusterPicker = document.querySelector("[data-cluster-picker]");
  if (clusterPicker) {
    const checkboxes = Array.from(clusterPicker.querySelectorAll("[data-cluster-checkbox]"));
    const hidden = document.querySelector("[data-cluster-ids]");
    const pickerLabel = clusterPicker.querySelector("[data-cluster-picker-label]");
    const pickerCount = clusterPicker.querySelector("[data-cluster-picker-count]");
    const maxSelected = Number.parseInt(clusterPicker.dataset.maxSelected || "10", 10);
    const updatePicker = (changed) => {
      const selected = checkboxes.filter((item) => item.checked);
      if (selected.length > maxSelected && changed) changed.checked = false;
      const bounded = checkboxes.filter((item) => item.checked);
      if (hidden) hidden.value = JSON.stringify(bounded.map((item) => item.value));
      const names = bounded.map((item) => item.closest("label")?.querySelector("strong")?.textContent || "cluster");
      if (pickerLabel) pickerLabel.textContent = names.length <= 2 ? names.join(", ") || "Select clusters" : `${names[0]}, ${names[1]} +${names.length - 2}`;
      if (pickerCount) pickerCount.textContent = `${bounded.length}/${maxSelected}`;
    };
    checkboxes.forEach((checkbox) => checkbox.addEventListener("change", () => updatePicker(checkbox)));
    clusterPicker.querySelector("[data-cluster-search]")?.addEventListener("input", (event) => {
      const query = event.target.value.trim().toLowerCase();
      clusterPicker.querySelectorAll("[data-cluster-option]").forEach((option) => {
        option.hidden = Boolean(query) && !option.dataset.search.toLowerCase().includes(query);
      });
    });
    updatePicker();
  }
  const appendOptimisticTurn = (question) => {
    const panel = document.querySelector(".ask-panel");
    if (!panel) return null;
    const empty = panel.querySelector(".ask-empty");
    if (empty) empty.hidden = true;
    let thread = panel.querySelector(".ask-thread");
    if (!thread) {
      thread = document.createElement("div");
      thread.className = "chat-thread ask-thread";
      thread.dataset.scrollLatest = "";
      panel.querySelector(".panel-header")?.insertAdjacentElement("afterend", thread);
    }
    const userMessage = document.createElement("article");
    userMessage.className = "chat-message chat-user optimistic-message";
    const userMeta = document.createElement("div");
    userMeta.className = "chat-meta";
    const userName = document.querySelector(".identity-copy strong")?.textContent || "You";
    const userStrong = document.createElement("strong");
    userStrong.textContent = userName;
    userMeta.append(userStrong);
    const userContent = document.createElement("div");
    userContent.className = "chat-markdown";
    userContent.textContent = question;
    userMessage.append(userMeta, userContent);

    const pending = document.createElement("article");
    pending.className = "chat-message chat-assistant chat-pending optimistic-message";
    const pendingMeta = document.createElement("div");
    pendingMeta.className = "chat-meta";
    const pendingStrong = document.createElement("strong");
    pendingStrong.textContent = "PodPilot";
    const pendingLabel = document.createElement("span");
    pendingLabel.textContent = "investigating";
    pendingMeta.append(pendingStrong, pendingLabel);
    const thinking = document.createElement("div");
    thinking.className = "thinking-state";
    thinking.setAttribute("role", "status");
    thinking.setAttribute("aria-live", "polite");
    const spinner = document.createElement("span");
    spinner.className = "thinking-spinner";
    spinner.setAttribute("aria-hidden", "true");
    const thinkingCopy = document.createElement("div");
    const thinkingTitle = document.createElement("strong");
    thinkingTitle.textContent = "Working on your question";
    const thinkingStatus = document.createElement("p");
    thinkingStatus.textContent = "Submitting the investigation…";
    thinkingCopy.append(thinkingTitle, thinkingStatus);
    thinking.append(spinner, thinkingCopy);
    pending.append(pendingMeta, thinking);
    thread.append(userMessage, pending);
    thread.scrollTop = thread.scrollHeight;
    return {empty, thread, nodes: [userMessage, pending]};
  };

  const pendingRun = document.querySelector(".chat-pending[data-adhoc-run-id]");
  if (pendingRun) {
    const current = pendingRun.querySelector("[data-progress-current]");
    const log = pendingRun.querySelector("[data-progress-log]");
    let lastSeq = Number.parseInt(log?.dataset.lastSeq || "-1", 10);
    const addProgress = (event) => {
      const seq = Number.parseInt(event.seq, 10);
      if (Number.isFinite(seq) && seq <= lastSeq) return;
      if (Number.isFinite(seq)) lastSeq = seq;
      if (current) current.textContent = event.message || "Investigation in progress.";
      if (log && event.message) {
        const item = document.createElement("li");
        if (Number.isFinite(seq)) item.dataset.seq = String(seq);
        item.append(document.createElement("span"), document.createTextNode(event.message));
        log.append(item);
        while (log.children.length > 5) log.firstElementChild?.remove();
      }
      const thread = pendingRun.closest(".ask-thread");
      thread?.scrollTo({top: thread.scrollHeight});
    };
    const finish = (payload) => {
      window.location.assign(payload.location || window.location.pathname);
    };
    let source = null;
    let poll = null;
    let progressStopped = false;
    const configuredTimeout = Number.parseInt(pendingRun.dataset.runTimeoutMs || "180000", 10);
    const reconcileStatus = async () => {
      if (progressStopped || !pendingRun.dataset.statusUrl) return false;
      try {
        const response = await fetch(pendingRun.dataset.statusUrl, {credentials: "same-origin"});
        if (!response.ok) return false;
        const payload = await response.json();
        payload.events?.forEach(addProgress);
        if (!["succeeded", "failed"].includes(payload.status)) return false;
        progressStopped = true;
        source?.close();
        if (poll) window.clearInterval(poll);
        window.clearTimeout(progressWatchdog);
        finish(payload);
        return true;
      } catch (_error) {
        return false;
      }
    };
    const progressWatchdog = window.setTimeout(async () => {
      if (await reconcileStatus()) return;
      progressStopped = true;
      source?.close();
      if (poll) window.clearInterval(poll);
      pendingRun.querySelector(".thinking-spinner")?.remove();
      if (current) current.textContent = "The investigation exceeded its progress deadline. Reload to check its final status.";
    }, (Number.isFinite(configuredTimeout) ? configuredTimeout : 180000) + 15000);
    if (window.EventSource && pendingRun.dataset.eventsUrl) {
      source = new EventSource(pendingRun.dataset.eventsUrl);
      source.addEventListener("progress", (event) => {
        try { addProgress(JSON.parse(event.data)); } catch (_error) { /* reconnect safely */ }
      });
      source.addEventListener("complete", (event) => {
        progressStopped = true;
        source.close();
        if (poll) window.clearInterval(poll);
        window.clearTimeout(progressWatchdog);
        try { finish(JSON.parse(event.data)); } catch (_error) { window.location.reload(); }
      });
      source.onerror = () => {
        if (!progressStopped && current) current.textContent = "Progress connection interrupted; reconnecting…";
        void reconcileStatus();
      };
    }
    poll = window.setInterval(() => { void reconcileStatus(); }, 1500);
  }

  if (adhocForm?.dataset.chatUrl) {
    adhocForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!csrf) return;
      const submit = adhocForm.querySelector('button[type="submit"]');
      const textarea = adhocForm.querySelector("textarea");
      const question = textarea?.value.trim() || "";
      if (!question) return;
      const requestBody = new URLSearchParams(new FormData(adhocForm));
      requestBody.set("message", question);
      const optimistic = appendOptimisticTurn(question);
      if (textarea) textarea.value = "";
      if (submit) { submit.disabled = true; submit.textContent = "Investigating…"; }
      try {
        const response = await fetch(adhocForm.dataset.chatUrl, {
          method: "POST",
          headers: {"X-PodPilot-CSRF": csrf, "Content-Type": "application/x-www-form-urlencoded"},
          credentials: "same-origin",
          body: requestBody,
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.detail || "PodPilot could not investigate this question.");
        }
        window.location.assign(response.url);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        optimistic?.nodes.forEach((node) => node.remove());
        if (optimistic?.empty) optimistic.empty.hidden = false;
        if (textarea) textarea.value = question;
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
  const evidenceDialog = document.querySelector("[data-evidence-dialog]");
  const evidenceToggle = document.querySelector("[data-evidence-open]");
  const openEvidence = () => {
    if (!evidenceDialog) return false;
    if (!evidenceDialog.open) evidenceDialog.showModal();
    evidenceToggle?.setAttribute("aria-expanded", "true");
    return true;
  };
  const focusEvidence = (target, {smooth = true} = {}) => {
    if (!target || !openEvidence()) return;
    document.querySelectorAll(".evidence-focus").forEach((item) => item.classList.remove("evidence-focus"));
    target.classList.add("evidence-focus");
    const technicalDetails = target.querySelector(".evidence-technical");
    document.querySelectorAll(".evidence-technical[open]").forEach((item) => {
      if (item !== technicalDetails) item.open = false;
    });
    if (technicalDetails) technicalDetails.open = true;
    requestAnimationFrame(() => {
      target.scrollIntoView({behavior: smooth ? "smooth" : "auto", block: "start"});
      target.focus({preventScroll: true});
    });
  };
  evidenceToggle?.addEventListener("click", openEvidence);
  document.querySelector("[data-evidence-close]")?.addEventListener("click", () => evidenceDialog?.close());
  evidenceDialog?.addEventListener("close", () => {
    evidenceToggle?.setAttribute("aria-expanded", "false");
    evidenceToggle?.focus();
  });
  evidenceDialog?.addEventListener("click", (event) => {
    if (event.target === evidenceDialog) evidenceDialog.close();
  });
  document.querySelectorAll('.chat-citations a[href^="#evidence-"]').forEach((link) => {
    link.addEventListener("click", (event) => {
      const target = document.getElementById(link.hash.slice(1));
      if (!target) return;
      event.preventDefault();
      focusEvidence(target);
      window.history.replaceState(null, "", link.hash);
    });
  });
  document.querySelectorAll('.answer-evidence a[href^="#evidence-"]').forEach((link) => {
    link.addEventListener("click", (event) => {
      const target = document.getElementById(link.hash.slice(1));
      if (!target) return;
      event.preventDefault();
      focusEvidence(target);
      window.history.replaceState(null, "", link.hash);
    });
  });
  if (window.location.hash.startsWith("#evidence-")) {
    const target = document.getElementById(window.location.hash.slice(1));
    if (target) focusEvidence(target, {smooth: false});
  }
  document.querySelectorAll("[data-csv-table]").forEach((button) => {
    button.addEventListener("click", () => {
      const table = document.getElementById(button.dataset.csvTable);
      if (!table) return;
      const escapeCell = (value) => {
        const safeValue = /^[=+\-@]/.test(value) ? `'${value}` : value;
        return `"${safeValue.replaceAll('"', '""')}"`;
      };
      const csv = Array.from(table.rows).map((row) =>
        Array.from(row.cells).map((cell) => escapeCell(cell.textContent.trim())).join(",")
      ).join("\r\n");
      const url = URL.createObjectURL(new Blob([csv], {type: "text/csv;charset=utf-8"}));
      const link = document.createElement("a");
      link.href = url;
      link.download = button.dataset.csvFilename || "podpilot-metrics.csv";
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    });
  });
  document.querySelectorAll(".delete-chat-form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!csrf || !form.dataset.deleteUrl) return;
      if (!window.confirm("Delete this conversation and its collected evidence? This cannot be undone.")) return;
      const button = form.querySelector('button[type="submit"]');
      if (button) { button.disabled = true; button.classList.add("is-busy"); button.setAttribute("aria-busy", "true"); }
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
        if (button) { button.disabled = false; button.classList.remove("is-busy"); button.removeAttribute("aria-busy"); }
      }
    });
  });
})();
