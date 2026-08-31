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
  const showToast = (message, tone = "error", timeout = 8000) => {
    if (!toast) return;
    toast.replaceChildren();
    const copy = document.createElement("span");
    copy.textContent = message;
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "toast-dismiss";
    dismiss.setAttribute("aria-label", "Dismiss notification");
    dismiss.textContent = "×";
    dismiss.addEventListener("click", () => { toast.hidden = true; });
    toast.append(copy, dismiss);
    toast.classList.toggle("success", tone === "success");
    toast.classList.toggle("warning", tone === "warning");
    toast.hidden = false;
    if (timeout > 0) window.setTimeout(() => { toast.hidden = true; }, timeout);
  };
  const pendingNotice = window.sessionStorage.getItem("podpilot-action-notice");
  if (pendingNotice && toast) {
    window.sessionStorage.removeItem("podpilot-action-notice");
    try {
      const notice = JSON.parse(pendingNotice);
      if (notice.message) {
        showToast(notice.message, notice.tone, notice.tone === "success" ? 5000 : 8000);
      }
      if (notice.focus === "probe-diagnostics") {
        const diagnostics = document.querySelector(".probe-diagnostics");
        if (diagnostics) diagnostics.open = true;
      }
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
    let response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: {"X-PodPilot-CSRF": csrf, "Content-Type": "application/x-www-form-urlencoded"},
        credentials: "same-origin",
        body,
      });
    } catch (_error) {
      throw new Error(
        "PodPilot did not return a response. Check the Route/OAuth proxy and the API pod logs, then try again.",
      );
    }
    const responseText = await response.text();
    let payload = {};
    try { payload = responseText ? JSON.parse(responseText) : {}; } catch (_error) { /* proxy text */ }
    if (!response.ok) {
      const proxyDetail = responseText && !responseText.trimStart().startsWith("<")
        ? responseText.trim().slice(0, 500)
        : "";
      throw new Error(payload.detail || proxyDetail || `PodPilot request failed (HTTP ${response.status}).`);
    }
    return payload;
  };
  if (settingsForm?.dataset.saveUrl) {
    const reasoningChecks = Array.from(
      settingsForm.querySelectorAll('input[name^="reasoning_effort_"]'),
    );
    const defaultReasoning = settingsForm.querySelector('select[name="default_reasoning_effort"]');
    const syncReasoningDefaults = () => {
      if (!defaultReasoning) return;
      const enabled = new Set(
        reasoningChecks.filter((item) => item.checked).map((item) => item.name.replace("reasoning_effort_", "")),
      );
      Array.from(defaultReasoning.options).forEach((option) => {
        option.disabled = Boolean(option.value) && !enabled.has(option.value);
      });
      if (defaultReasoning.value && !enabled.has(defaultReasoning.value)) {
        defaultReasoning.value = "";
      }
    };
    reasoningChecks.forEach((item) => item.addEventListener("change", syncReasoningDefaults));
    syncReasoningDefaults();
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
          : {focus: "probe-diagnostics"};
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

  const setupTagEditor = (form, {onChange} = {}) => {
    const tagEditor = form?.querySelector("[data-tag-editor]");
    if (!tagEditor) return {commit: () => true, tags: new Map()};
    const tagInput = tagEditor.querySelector("[data-tag-input]");
    const tagList = tagEditor.querySelector("[data-tag-list]");
    const tagValue = form.querySelector("[data-tags-value]");
    const tagError = form.querySelector("[data-tag-error]");
    const tags = new Map();
    const showError = (message = "") => {
      if (!tagError) return;
      tagError.textContent = message;
      tagError.hidden = !message;
    };
    const sync = () => {
      if (tagValue) {
        tagValue.value = JSON.stringify(Object.fromEntries(
          Array.from(tags.entries()).sort(([left], [right]) => left.localeCompare(right)),
        ));
      }
      tagList?.replaceChildren();
      tags.forEach((value, key) => {
        const chip = document.createElement("span");
        chip.className = "tag-chip";
        const copy = document.createElement("span");
        copy.textContent = value ? `${key}:${value}` : key;
        const remove = document.createElement("button");
        remove.type = "button";
        remove.setAttribute("aria-label", `Remove tag ${copy.textContent}`);
        remove.textContent = "×";
        remove.addEventListener("click", () => {
          tags.delete(key);
          sync();
          tagInput?.focus();
        });
        chip.append(copy, remove);
        tagList?.append(chip);
      });
      onChange?.(tags);
    };
    const add = (rawTag) => {
      const tag = rawTag.trim();
      if (!tag) return true;
      const separator = tag.indexOf(":");
      const key = (separator === -1 ? tag : tag.slice(0, separator)).trim();
      const value = (separator === -1 ? "" : tag.slice(separator + 1)).trim();
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/.test(key)) {
        showError("Tag names may use letters, numbers, dots, underscores, and hyphens.");
        return false;
      }
      if (separator !== -1 && !value) {
        showError("Add a value after the colon, or remove the colon for a single-word tag.");
        return false;
      }
      if (value && !/^[A-Za-z0-9][A-Za-z0-9_.:/ -]{0,126}$/.test(value)) {
        showError("Tag values may use letters, numbers, spaces, dots, underscores, slashes, colons, and hyphens.");
        return false;
      }
      if (!tags.has(key) && tags.size >= 30) {
        showError("A tag set can contain at most 30 tags.");
        return false;
      }
      tags.set(key, value);
      showError();
      sync();
      return true;
    };
    const commit = () => {
      if (!tagInput?.value.trim()) return true;
      const rawTags = tagInput.value.split(",").map((item) => item.trim()).filter(Boolean);
      for (const rawTag of rawTags) {
        if (!add(rawTag)) return false;
      }
      tagInput.value = "";
      return true;
    };
    try {
      Object.entries(JSON.parse(tagEditor.dataset.tags || "{}")).forEach(([key, value]) => {
        tags.set(String(key), String(value));
      });
    } catch (_error) { /* server data is validated before rendering */ }
    sync();
    tagInput?.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === ",") {
        event.preventDefault();
        commit();
      } else if (event.key === "Backspace" && !tagInput.value && tags.size) {
        const lastKey = Array.from(tags.keys()).at(-1);
        tags.delete(lastKey);
        sync();
      }
    });
    tagInput?.addEventListener("blur", commit);
    tagEditor.addEventListener("click", () => tagInput?.focus());
    return {commit, input: tagInput, tags};
  };

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
    const matchPreview = knowledgeForm.querySelector("[data-knowledge-tag-matches]");
    const knowledgeTags = setupTagEditor(knowledgeForm, {onChange: (requiredTags) => {
      if (!matchPreview) return;
      if (!requiredTags.size) {
        matchPreview.textContent = "No required tags: use explicit clusters above or leave both empty for global knowledge.";
        return;
      }
      const matchingNames = knowledgeClusterBoxes.filter((item) => {
        try {
          const clusterTags = JSON.parse(item.dataset.clusterTags || "{}");
          return Array.from(requiredTags).every(([key, value]) => clusterTags[key] === value);
        } catch (_error) { return false; }
      }).map((item) => item.dataset.clusterName || item.value);
      matchPreview.textContent = matchingNames.length
        ? `Tag match: ${matchingNames.join(", ")}.`
        : "No configured clusters currently match every required tag.";
    }});
    knowledgeClusterBoxes.forEach((item) => item.addEventListener("change", syncKnowledgeClusters));
    syncKnowledgeClusters();
    knowledgeForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!knowledgeTags.commit()) {
        knowledgeTags.input?.focus();
        return;
      }
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
    const clusterTagEditor = setupTagEditor(clusterSettingsForm);
    verifyCheckbox?.addEventListener("change", () => {
      if (verifyValue) verifyValue.value = verifyCheckbox.checked ? "true" : "false";
    });
    clusterSettingsForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!clusterTagEditor.commit()) {
        clusterTagEditor.input?.focus();
        return;
      }
      const submit = clusterSettingsForm.querySelector('button[type="submit"]');
      const priorSubmitText = submit?.textContent || "Save cluster";
      if (submit) { submit.disabled = true; submit.textContent = "Saving…"; }
      try {
        const payload = await sendSettingsRequest(
          clusterSettingsForm.dataset.saveUrl,
          new URLSearchParams(new FormData(clusterSettingsForm)),
        );
        window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify({
          tone: "success",
          message: payload.detail || clusterSettingsForm.dataset.successMessage || "Cluster connection saved. Test it before using it for Ask PodPilot.",
        }));
        const redirectBase = clusterSettingsForm.dataset.redirectBase || "/settings/clusters";
        window.location.assign(`${redirectBase}?edit=${encodeURIComponent(payload.cluster_id)}`);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        if (submit) { submit.disabled = false; submit.textContent = priorSubmitText; }
      }
    });
  }
  document.querySelectorAll(".cluster-action").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!button.dataset.actionUrl) return;
      if (button.dataset.confirm && !window.confirm(button.dataset.confirm)) return;
      button.disabled = true;
      const prior = button.textContent;
      button.textContent = button.dataset.actionKind === "test"
        ? "Testing…"
        : button.dataset.actionKind === "delete" ? "Removing…" : "Disabling…";
      try {
        const payload = await sendSettingsRequest(button.dataset.actionUrl, "");
        const passed = payload.status === "ready";
        window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify({
          tone: passed || ["disabled", "deleted"].includes(payload.status) ? "success" : "error",
          message: payload.detail || (
            payload.status === "deleted" ? "Personal cluster removed."
              : payload.status === "disabled" ? "Cluster disabled and token removed."
                : "Cluster connection tested."
          ),
        }));
        if (button.dataset.redirectUrl) {
          window.location.assign(button.dataset.redirectUrl);
        } else {
          window.location.reload();
        }
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
  const starterButtons = Array.from(document.querySelectorAll("[data-starter-prompt]"));
  const starterActions = Array.from(document.querySelectorAll("[data-starter-available]"));
  const clusterPicker = document.querySelector("[data-cluster-picker]");
  const executionMode = adhocForm?.querySelector('[name="execution_mode"]');
  const askSubmit = adhocForm?.querySelector("[data-ask-submit]");
  const askLayout = document.querySelector("[data-ask-layout]");
  const composerTextarea = adhocForm?.querySelector("textarea[name='message']");
  const composerDraftKey = adhocForm?.dataset.chatUrl
    ? `podpilot-composer-draft:${adhocForm.dataset.chatUrl}`
    : null;
  if (composerTextarea && !composerTextarea.disabled) {
    const savedDraft = composerDraftKey ? window.sessionStorage.getItem(composerDraftKey) : "";
    if (!composerTextarea.value && savedDraft) composerTextarea.value = savedDraft;
    composerTextarea.addEventListener("input", () => {
      if (!composerDraftKey) return;
      if (composerTextarea.value) window.sessionStorage.setItem(composerDraftKey, composerTextarea.value);
      else window.sessionStorage.removeItem(composerDraftKey);
    });
    window.requestAnimationFrame(() => composerTextarea.focus({preventScroll: true}));
  }
  if (executionMode && askSubmit) {
    const updateModeAvailability = () => {
      askLayout?.classList.toggle("action-session", executionMode.value === "action");
      const ready = executionMode.value === "action"
        ? adhocForm.dataset.actionModelReady === "true"
        : adhocForm.dataset.readOnlyModelReady === "true";
      askSubmit.disabled = !ready;
      askSubmit.textContent = "Submit";
    };
    executionMode.addEventListener("change", updateModeAvailability);
    updateModeAvailability();
  }
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
      if (clusterPicker.closest("[data-delegated-connect-form]")) {
        const selectedEnvironment = bounded[0]?.dataset.environment || "";
        checkboxes.forEach((item) => {
          if (!item.checked) {
            item.disabled = item.dataset.connected === "true" || Boolean(
              selectedEnvironment && item.dataset.environment !== selectedEnvironment
            );
          }
        });
      }
      if (hidden) hidden.value = JSON.stringify(bounded.map((item) => item.value));
      const names = bounded.map((item) => item.closest("label")?.querySelector("strong")?.textContent || "cluster");
      if (pickerLabel) {
        pickerLabel.replaceChildren();
        if (names.length) {
          names.forEach((name) => {
            const chip = document.createElement("span");
            chip.className = "cluster-picker-chip";
            chip.textContent = name;
            pickerLabel.append(chip);
          });
        } else {
          const placeholder = document.createElement("span");
          placeholder.className = "cluster-picker-placeholder";
          placeholder.textContent = "Select clusters";
          pickerLabel.append(placeholder);
        }
        pickerLabel.setAttribute("aria-label", names.length ? `Selected clusters: ${names.join(", ")}` : "No clusters selected");
      }
      if (pickerCount) pickerCount.textContent = `${bounded.length}/${maxSelected}`;
      starterActions.forEach((button) => {
        button.disabled = button.dataset.starterAvailable !== "true" || bounded.length === 0;
      });
    };
    checkboxes.forEach((checkbox) => checkbox.addEventListener("change", () => {
      if (
        checkbox.checked
        && checkbox.dataset.connected === "false"
        && checkbox.dataset.loginUrl
        && !clusterPicker.closest("[data-delegated-connect-form]")
      ) {
        const requestedIds = checkboxes.filter((item) => item.checked).map((item) => item.value);
        const loginUrl = new URL(checkbox.dataset.loginUrl, window.location.origin);
        loginUrl.searchParams.set("retry", checkbox.value);
        loginUrl.searchParams.set(
          "next",
          `/ask?new=1&cluster_ids=${requestedIds.join(",")}`,
        );
        checkbox.checked = false;
        window.location.assign(loginUrl.toString());
        return;
      }
      updatePicker(checkbox);
    }));
    clusterPicker.querySelector("[data-cluster-search]")?.addEventListener("input", (event) => {
      const query = event.target.value.trim().toLowerCase();
      clusterPicker.querySelectorAll("[data-cluster-option]").forEach((option) => {
        option.hidden = Boolean(query) && !option.dataset.search.toLowerCase().includes(query);
      });
    });
    updatePicker();
  }
  starterButtons.forEach((button) => {
    button.addEventListener("click", () => {
      if (!adhocForm || button.disabled) return;
      const selected = Array.from(
        adhocForm.querySelectorAll("[data-cluster-checkbox]:checked")
      );
      if (!selected.length) {
        if (clusterPicker) clusterPicker.open = true;
        if (toast) {
          toast.textContent = "Select at least one cluster before starting an investigation.";
          toast.hidden = false;
        }
        return;
      }
      const textarea = adhocForm.querySelector("textarea[name='message']");
      if (!textarea) return;
      textarea.value = button.dataset.starterPrompt || "";
      textarea.dispatchEvent(new Event("input", {bubbles: true}));
      adhocForm.requestSubmit();
    });
  });
  const workloadStarterForm = document.querySelector("[data-workload-starter-form]");
  document.querySelector("[data-workload-starter-open]")?.addEventListener("click", () => {
    if (!workloadStarterForm) return;
    workloadStarterForm.hidden = false;
    workloadStarterForm.querySelector("input[name='namespace']")?.focus();
  });
  document.querySelector("[data-workload-starter-cancel]")?.addEventListener("click", () => {
    if (workloadStarterForm) workloadStarterForm.hidden = true;
  });
  workloadStarterForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!adhocForm || !workloadStarterForm.checkValidity()) return;
    const namespace = workloadStarterForm.elements.namespace.value.trim();
    const resource = workloadStarterForm.elements.resource.value.trim();
    const textarea = adhocForm.querySelector("textarea[name='message']");
    if (!namespace || !resource || !textarea) return;
    textarea.value = `Troubleshoot the workload or Pod named ${resource} in namespace ${namespace} across the selected clusters. Use read-only checks to inspect status, owner relationships, events, readiness, and relevant bounded logs. Cite observed evidence and do not make changes.`;
    textarea.dispatchEvent(new Event("input", {bubbles: true}));
    adhocForm.requestSubmit();
  });
  const delegatedConnectForm = document.querySelector("[data-delegated-connect-form]");
  if (delegatedConnectForm?.dataset.connectUrl) {
    delegatedConnectForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!csrf) return;
      const submit = delegatedConnectForm.querySelector('button[type="submit"]');
      if (submit) { submit.disabled = true; submit.textContent = "Connecting…"; }
      try {
        const response = await fetch(delegatedConnectForm.dataset.connectUrl, {
          method: "POST",
          headers: {"X-PodPilot-CSRF": csrf, "Content-Type": "application/x-www-form-urlencoded"},
          credentials: "same-origin",
          body: new URLSearchParams(new FormData(delegatedConnectForm)),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          const failedNames = Array.isArray(payload.failed)
            ? payload.failed.map((item) => item.cluster_name).filter(Boolean)
            : [];
          throw new Error(
            failedNames.length
              ? `${payload.detail || "Cluster login failed"} ${failedNames.join(", ")}. Check the credentials and retry.`
              : payload.detail || "PodPilot could not connect the selected clusters.",
          );
        }
        const failedItems = Array.isArray(payload.failed) ? payload.failed : [];
        const failed = failedItems.length;
        window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify({
          tone: failed ? "warning" : "success",
          message: failed
            ? `${payload.connected.length} cluster(s) connected. Retry required for: ${failedItems.map((item) => item.cluster_name).join(", ")}.`
            : `${payload.connected.length} cluster(s) connected.`,
        }));
        const nextUrl = delegatedConnectForm.elements.next_url?.value || "/ask?new=1";
        if (failed) {
          const retryUrl = new URL("/delegated/connect", window.location.origin);
          retryUrl.searchParams.set("retry", failedItems.map((item) => item.cluster_id).join(","));
          retryUrl.searchParams.set("next", nextUrl.startsWith("/ask") ? nextUrl : "/ask?new=1");
          window.location.assign(`${retryUrl.pathname}${retryUrl.search}`);
        } else {
          window.location.assign(nextUrl.startsWith("/ask") ? nextUrl : "/ask?new=1");
        }
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
      if (submit) { submit.disabled = false; submit.textContent = "Add selected clusters"; }
    }
  });
}
  document.querySelectorAll("[data-delegated-remove-url]").forEach((button) => {
    button.addEventListener("click", async () => {
      const clusterName = button.dataset.clusterName || "this cluster";
      if (!csrf || !window.confirm(`Remove and revoke the ${clusterName} sign-in? Existing conversations that use it will require reconnection.`)) return;
      button.disabled = true;
      button.textContent = "Removing…";
      try {
        const response = await fetch(button.dataset.delegatedRemoveUrl, {
          method: "POST",
          headers: {"X-PodPilot-CSRF": csrf},
          credentials: "same-origin",
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || "PodPilot could not remove the cluster sign-in.");
        window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify({
          tone: "success",
          message: `${clusterName} was removed from this PodPilot session.`,
        }));
        window.location.assign("/delegated/connect");
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        button.disabled = false;
        button.textContent = "Remove";
      }
    });
  });
  document.querySelector("[data-delegated-disconnect-url]")?.addEventListener("click", async (event) => {
    const button = event.currentTarget;
    if (!csrf || !window.confirm("Clear and revoke every current cluster sign-in? Your saved cluster list and conversations will remain.")) return;
    button.disabled = true;
    button.textContent = "Removing…";
    try {
      const response = await fetch(button.dataset.delegatedDisconnectUrl, {
        method: "POST",
        headers: {"X-PodPilot-CSRF": csrf},
        credentials: "same-origin",
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail || "PodPilot could not clear the cluster sign-ins.");
      window.sessionStorage.setItem("podpilot-action-notice", JSON.stringify({
        tone: "success",
        message: "Cluster sign-ins cleared. Select clusters and sign in again.",
      }));
      window.location.assign("/delegated/connect");
    } catch (error) {
      if (toast) { toast.textContent = error.message; toast.hidden = false; }
      button.disabled = false;
      button.textContent = "Remove all sign-ins";
    }
  });
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
    thinkingTitle.textContent = "Live investigation";
    const thinkingStatus = document.createElement("p");
    thinkingStatus.textContent = "Submitting the investigation…";
    thinkingCopy.append(thinkingTitle, thinkingStatus);
    thinking.append(spinner, thinkingCopy);
    pending.append(pendingMeta, thinking);
    thread.append(userMessage, pending);
    thread.scrollTop = thread.scrollHeight;
    return {empty, thread, nodes: [userMessage, pending]};
  };

  document.querySelectorAll("[data-followup-form]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!csrf) return;
      const button = form.querySelector('button[type="submit"]');
      const label = form.querySelector("strong")?.textContent?.trim() || "Suggested check";
      const optimistic = appendOptimisticTurn(`Run suggested check: ${label}`);
      if (button) { button.disabled = true; button.textContent = "Starting…"; }
      try {
        const response = await fetch(form.action, {
          method: "POST",
          headers: {"X-PodPilot-CSRF": csrf},
          credentials: "same-origin",
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.detail || "PodPilot could not run this suggested check.");
        }
        window.location.assign(response.url);
      } catch (error) {
        optimistic?.nodes.forEach((node) => node.remove());
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        if (button) { button.disabled = false; button.textContent = "Run check"; }
      }
    });
  });

  const pendingRun = document.querySelector(".chat-pending[data-adhoc-run-id]");
  if (pendingRun) {
    const progressTitle = pendingRun.querySelector("[data-progress-title]");
    const current = pendingRun.querySelector("[data-progress-current]");
    const log = pendingRun.querySelector("[data-progress-log]");
    let lastSeq = Number.parseInt(log?.dataset.lastSeq || "-1", 10);
    const progressItemsPerPhase = 3;
    const displayedProgressMessages = new Set(
      Array.from(log?.querySelectorAll("[data-progress-items] li") || [], (item) => item.textContent)
    );
    const appendPhaseUpdate = (event, seq) => {
      if (!log || !event.message || displayedProgressMessages.has(event.message)) return;
      displayedProgressMessages.add(event.message);
      const phaseName = event.phase || "investigating";
      const phaseGroups = Array.from(log.querySelectorAll("[data-progress-phase]"));
      let group = phaseGroups.find((item) => item.dataset.progressPhase === phaseName);
      if (!group) {
        group = document.createElement("li");
        group.className = "progress-phase";
        group.dataset.progressPhase = phaseName;
        const heading = document.createElement("div");
        heading.className = "progress-phase-heading";
        const marker = document.createElement("span");
        marker.setAttribute("aria-hidden", "true");
        const label = document.createElement("small");
        label.textContent = phaseName.replaceAll("_", " ");
        heading.append(marker, label);
        const items = document.createElement("ul");
        items.className = "progress-phase-updates";
        items.dataset.progressItems = "";
        group.append(heading, items);
        log.append(group);
      }
      const items = group.querySelector("[data-progress-items]");
      if (!items) return;
      const item = document.createElement("li");
      if (Number.isFinite(seq)) item.dataset.seq = String(seq);
      item.textContent = event.message;
      items.append(item);
      while (items.children.length > progressItemsPerPhase) items.firstElementChild?.remove();
    };
    const addProgress = (event) => {
      const seq = Number.parseInt(event.seq, 10);
      if (Number.isFinite(seq) && seq <= lastSeq) return;
      if (Number.isFinite(seq)) lastSeq = seq;
      if (progressTitle && event.phase) {
        progressTitle.textContent = event.phase === "queued" ? "Waiting to investigate" : "Live investigation";
      }
      if (current) current.textContent = event.message || "Investigation in progress.";
      appendPhaseUpdate(event, seq);
      const thread = pendingRun.closest(".ask-thread");
      thread?.scrollTo({top: thread.scrollHeight});
    };
    const finish = (payload) => {
      window.location.assign(payload.location || window.location.pathname);
    };
    let source = null;
    let poll = null;
    let progressStopped = false;
    const cancelRun = pendingRun.querySelector("[data-run-cancel]");
    cancelRun?.addEventListener("click", async () => {
      if (!csrf || !pendingRun.dataset.cancelUrl) return;
      if (!window.confirm(
        "Cancel this investigation? PodPilot will attempt to stop the active model request and oc command. Operations that already completed cannot be rolled back."
      )) return;
      cancelRun.disabled = true;
      cancelRun.textContent = "Cancelling…";
      if (current) current.textContent = "Requesting best-effort cancellation…";
      try {
        const response = await fetch(pendingRun.dataset.cancelUrl, {
          method: "POST",
          headers: {"X-PodPilot-CSRF": csrf},
          credentials: "same-origin",
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.detail || "PodPilot could not cancel this request.");
        progressStopped = true;
        source?.close();
        if (poll) window.clearInterval(poll);
        window.clearTimeout(progressWatchdog);
        window.location.assign(payload.location || window.location.pathname);
      } catch (error) {
        if (toast) { toast.textContent = error.message; toast.hidden = false; }
        cancelRun.disabled = false;
        cancelRun.textContent = "Cancel request";
      }
    });
    const configuredTimeout = Number.parseInt(pendingRun.dataset.runTimeoutMs || "180000", 10);
    const reconcileStatus = async () => {
      if (progressStopped || !pendingRun.dataset.statusUrl) return false;
      try {
        const response = await fetch(pendingRun.dataset.statusUrl, {credentials: "same-origin"});
        if (!response.ok) return false;
        const payload = await response.json();
        payload.events?.forEach(addProgress);
        if (!["succeeded", "failed", "cancelled"].includes(payload.status)) return false;
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
      const rawResponseToggle = adhocForm.querySelector('input[name="include_raw_response"]');
      const reasoningSelect = adhocForm.querySelector('select[name="reasoning_effort"]');
      const question = textarea?.value.trim() || "";
      if (!question) return;
      const requestBody = new URLSearchParams(new FormData(adhocForm));
      requestBody.set("message", question);
      const optimistic = appendOptimisticTurn(question);
      if (textarea) textarea.value = "";
      if (composerDraftKey) window.sessionStorage.removeItem(composerDraftKey);
      textarea?.focus({preventScroll: true});
      if (rawResponseToggle) rawResponseToggle.disabled = true;
      if (reasoningSelect) reasoningSelect.disabled = true;
      if (submit) { submit.disabled = true; submit.textContent = "Submitting…"; }
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
        if (composerDraftKey) window.sessionStorage.setItem(composerDraftKey, question);
        if (rawResponseToggle) rawResponseToggle.disabled = false;
        if (reasoningSelect) reasoningSelect.disabled = false;
        if (submit) { submit.disabled = false; submit.textContent = "Submit"; }
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
      if (!window.confirm("Delete this conversation and its collected evidence? Any queued or running investigation will be cancelled. This cannot be undone.")) return;
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
