(() => {
  async function post(url, payload) {
    const response = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json',
      'X-PodPilot-CSRF': document.querySelector('meta[name="podpilot-csrf"]')?.content || ''},
      body: JSON.stringify(payload || {})});
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Request failed.');
    return result;
  }

  let preferLatestRun = false;
  function bindPostButtons(root = document) {
    root.querySelectorAll('[data-incident-post]:not([data-incident-post-bound])').forEach(button => {
      button.dataset.incidentPostBound = 'true';
      button.addEventListener('click', async () => {
        const connectorForm = button.closest('#incident-connection-form');
        const isDiscovery = button.dataset.incidentPost.endsWith('/test');
        if (isDiscovery && connectorForm?.dataset.unsaved === 'true') {
          const feedback = document.getElementById('incident-feedback');
          if (feedback) feedback.textContent = 'Save your changes first. Test & discover uses the saved configuration and saved token.';
          return;
        }
        const originalLabel = button.textContent;
        button.disabled = true;
        button.setAttribute('aria-busy', 'true');
        if (isDiscovery) button.textContent = 'Queuing test…';
        if (button.hasAttribute('data-incident-rerun')) preferLatestRun = true;
        try {
          const result = await post(button.dataset.incidentPost);
          if (result.url) { window.location.assign(result.url); return; }
          if (button.hasAttribute('data-incident-rerun')) { window.location.reload(); return; }
          const feedback = document.getElementById('incident-feedback');
          if (feedback) feedback.textContent = result.checks ? result.checks.join(' · ') :
            result.discovery_status ? `Discovery ${result.discovery_status}. Testing saved credentials; results update below.` :
              'Investigation queued. Live progress will appear automatically.';
        } catch (error) {
          preferLatestRun = false;
          const feedback = document.getElementById('incident-feedback');
          if (feedback) feedback.textContent = error.message;
        } finally { button.disabled = false; button.removeAttribute('aria-busy'); button.textContent = originalLabel; }
      });
    });
  }

  function bindEvidenceDialogs(root) {
    root.querySelectorAll('[data-incident-evidence-open]:not([data-incident-evidence-bound])').forEach(button => {
      button.dataset.incidentEvidenceBound = 'true';
      button.addEventListener('click', () => {
        const dialog = document.getElementById(button.dataset.incidentEvidenceOpen);
        if (!dialog) return;
        if (typeof dialog.showModal === 'function') dialog.showModal();
        else dialog.setAttribute('open', '');
      });
    });
    root.querySelectorAll('[data-incident-evidence-dialog]:not([data-incident-evidence-bound])').forEach(dialog => {
      dialog.dataset.incidentEvidenceBound = 'true';
      dialog.querySelector('[data-incident-evidence-close]')?.addEventListener('click', () => dialog.close());
      dialog.addEventListener('click', event => {
        if (event.target !== dialog) return;
        const bounds = dialog.getBoundingClientRect();
        const inside = event.clientX >= bounds.left && event.clientX <= bounds.right &&
          event.clientY >= bounds.top && event.clientY <= bounds.bottom;
        if (!inside) dialog.close();
      });
    });
  }

  function bindTabs(tabsRoot, preferredPanelId = null) {
    bindEvidenceDialogs(tabsRoot);
    const tabs = Array.from(tabsRoot.querySelectorAll('[data-incident-tab]'));
    const panels = Array.from(tabsRoot.querySelectorAll('[data-incident-tab-panel]'));
    function activate(panelId, updateHash = false) {
      const selected = tabs.find(tab => tab.dataset.incidentTab === panelId);
      if (!selected) return;
      tabs.forEach(tab => {
        const active = tab === selected;
        tab.setAttribute('aria-selected', String(active));
        tab.tabIndex = active ? 0 : -1;
      });
      panels.forEach(panel => { panel.hidden = panel.id !== panelId; });
      if (updateHash) history.replaceState(null, '', '#' + panelId);
    }
    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => activate(tab.dataset.incidentTab, true));
      tab.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 :
          (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
        tabs[next].focus(); activate(tabs[next].dataset.incidentTab, true);
      });
    });
    function revealEvidence(target, updateHash = true) {
      if (!target) return;
      const panel = target.closest('[data-incident-tab-panel]');
      if (panel) activate(panel.id, false);
      if (updateHash) history.replaceState(null, '', '#' + target.id);
      requestAnimationFrame(() => {
        target.scrollIntoView({behavior: 'smooth', block: 'center'});
        target.classList.add('evidence-highlight');
        window.setTimeout(() => target.classList.remove('evidence-highlight'), 1800);
        const dialog = document.getElementById(target.dataset.incidentEvidenceOpen);
        if (dialog && !dialog.open) {
          if (typeof dialog.showModal === 'function') dialog.showModal();
          else dialog.setAttribute('open', '');
        }
      });
    }
    tabsRoot.querySelectorAll('[data-evidence-link]').forEach(link => link.addEventListener('click', event => {
      event.preventDefault();
      revealEvidence(document.getElementById(link.hash.slice(1)));
    }));
    const initialTarget = preferredPanelId ? document.getElementById(preferredPanelId) :
      (location.hash ? document.getElementById(location.hash.slice(1)) : null);
    if (initialTarget?.matches('[data-incident-tab-panel]')) activate(initialTarget.id, false);
    else if (initialTarget?.matches('[data-incident-evidence-open]')) revealEvidence(initialTarget, false);
  }

  function openIds(root, attribute) {
    return new Set(Array.from(root.querySelectorAll(`details[${attribute}][open]`))
      .map(item => item.getAttribute(attribute)));
  }
  function restoreOpen(root, attribute, values) {
    root.querySelectorAll(`details[${attribute}]`).forEach(item => {
      item.open = values.has(item.getAttribute(attribute));
    });
  }
  function setLiveState(root, state, label) {
    const status = root?.querySelector('[data-live-status]');
    if (!status) return;
    status.dataset.liveState = state;
    status.textContent = label;
  }
  function connectLive(getRoot, refresh) {
    const root = getRoot();
    const eventsUrl = root?.dataset.eventsUrl;
    if (!eventsUrl) return () => {};
    let source;
    let fallbackTimer;
    let stopped = false;
    const fallback = () => {
      if (stopped) return;
      window.clearTimeout(fallbackTimer);
      fallbackTimer = window.setTimeout(async () => {
        if (stopped) return;
        await refresh();
        fallback();
      }, 4000);
    };
    if (window.EventSource) {
      source = new EventSource(eventsUrl);
      source.addEventListener('open', () => {
        if (stopped) return;
        setLiveState(getRoot(), 'live', 'Live updates');
      });
      source.addEventListener('update', refresh);
      source.addEventListener('error', () => {
        if (stopped) return;
        setLiveState(getRoot(), 'reconnecting', 'Reconnecting…');
        fallback();
      });
    } else {
      setLiveState(getRoot(), 'reconnecting', 'Auto-updating');
      fallback();
    }
    // Poll even when a proxy accepts an SSE connection but buffers every event.
    fallback();
    const stop = () => {
      stopped = true;
      source?.close();
      window.clearTimeout(fallbackTimer);
    };
    window.addEventListener('pagehide', stop, {once: true});
    return stop;
  }

  bindPostButtons();
  let incidentDetail = document.querySelector('[data-incident-detail]');
  if (incidentDetail) {
    bindTabs(incidentDetail);
    let refreshRunning = false;
    let refreshPending = false;
    let stopDetailLive = () => {};
    async function refreshDetail() {
      if (refreshRunning) { refreshPending = true; return; }
      refreshRunning = true;
      try {
        const response = await fetch(window.location.href, {
          headers: {'X-PodPilot-Activity-Refresh': '1'}, cache: 'no-store'
        });
        if (!response.ok) throw new Error('Incident refresh failed.');
        const documentCopy = new DOMParser().parseFromString(await response.text(), 'text/html');
        const replacement = documentCopy.querySelector('[data-incident-detail]');
        if (replacement && replacement.dataset.stateVersion !== incidentDetail.dataset.stateVersion) {
          const selected = incidentDetail.querySelector('[data-incident-tab][aria-selected="true"]')?.dataset.incidentTab;
          const expandedDetails = openIds(incidentDetail, 'data-incident-detail-open-id');
          const openEvidenceDialog = incidentDetail.querySelector('[data-incident-evidence-dialog][open]')?.id;
          incidentDetail.replaceWith(replacement);
          incidentDetail = replacement;
          bindPostButtons(incidentDetail);
          const latest = preferLatestRun ?
            incidentDetail.querySelector('[data-incident-tab]')?.dataset.incidentTab : null;
          bindTabs(incidentDetail, latest || selected);
          restoreOpen(incidentDetail, 'data-incident-detail-open-id', expandedDetails);
          if (openEvidenceDialog) document.getElementById(openEvidenceDialog)?.showModal();
          preferLatestRun = false;
          if (incidentDetail.dataset.investigationActive !== 'true') stopDetailLive();
        }
        setLiveState(incidentDetail, 'live', 'Live updates');
      } catch (_error) {
        setLiveState(incidentDetail, 'reconnecting', 'Reconnecting…');
      } finally {
        refreshRunning = false;
        if (refreshPending) { refreshPending = false; refreshDetail(); }
      }
    }
    if (incidentDetail.dataset.investigationActive === 'true') {
      stopDetailLive = connectLive(() => incidentDetail, refreshDetail);
    }
  }

  let incidentBoard = document.querySelector('[data-incident-dashboard]');
  if (incidentBoard) {
    let refreshRunning = false;
    let refreshPending = false;
    let interactionUntil = 0;
    document.addEventListener('pointerdown', event => {
      if (event.target.closest?.('[data-incident-dashboard]')) interactionUntil = Date.now() + 1500;
    }, true);
    async function refreshActivity() {
      if (document.hidden) return;
      if (Date.now() < interactionUntil) {
        window.setTimeout(refreshActivity, interactionUntil - Date.now() + 50);
        return;
      }
      if (refreshRunning) { refreshPending = true; return; }
      refreshRunning = true;
      const expandedIncidents = openIds(incidentBoard, 'data-incident-activity-id');
      const expandedSpecialists = openIds(incidentBoard, 'data-specialist-activity-id');
      try {
        const response = await fetch(window.location.href, {
          headers: {'X-PodPilot-Activity-Refresh': '1'}, cache: 'no-store'
        });
        if (!response.ok) throw new Error('Incident activity refresh failed.');
        const documentCopy = new DOMParser().parseFromString(await response.text(), 'text/html');
        const replacement = documentCopy.querySelector('[data-incident-dashboard]');
        if (replacement && Date.now() >= interactionUntil && replacement.innerHTML !== incidentBoard.innerHTML) {
          incidentBoard.replaceWith(replacement);
          incidentBoard = replacement;
          restoreOpen(incidentBoard, 'data-incident-activity-id', expandedIncidents);
          restoreOpen(incidentBoard, 'data-specialist-activity-id', expandedSpecialists);
        }
        setLiveState(incidentBoard, 'live', 'Live updates');
      } catch (_error) {
        setLiveState(incidentBoard, 'reconnecting', 'Reconnecting…');
      } finally {
        refreshRunning = false;
        if (refreshPending) { refreshPending = false; refreshActivity(); }
      }
    }
    connectLive(() => incidentBoard, refreshActivity);
  }

  let connectorTopology = document.querySelector('[data-connector-topology]');
  if (connectorTopology) {
    let refreshRunning = false;
    let refreshPending = false;
    async function refreshConnectorTopology() {
      if (refreshRunning) { refreshPending = true; return; }
      refreshRunning = true;
      try {
        const response = await fetch(window.location.href, {cache: 'no-store'});
        if (!response.ok) throw new Error('Connector discovery refresh failed.');
        const documentCopy = new DOMParser().parseFromString(await response.text(), 'text/html');
        const replacement = documentCopy.querySelector('[data-connector-topology]');
        if (replacement && replacement.innerHTML !== connectorTopology.innerHTML) {
          connectorTopology.replaceWith(replacement);
          connectorTopology = replacement;
        }
        setLiveState(connectorTopology, 'live', 'Live discovery');
      } catch (_error) {
        setLiveState(connectorTopology, 'reconnecting', 'Reconnecting…');
      } finally {
        refreshRunning = false;
        if (refreshPending) { refreshPending = false; refreshConnectorTopology(); }
      }
    }
    connectLive(() => connectorTopology, refreshConnectorTopology);
  }

  const form = document.getElementById('incident-connection-form');
  if (!form) return;
  form.addEventListener('input', () => { form.dataset.unsaved = 'true'; });
  form.addEventListener('change', () => { form.dataset.unsaved = 'true'; });
  function visibility() {
    document.querySelectorAll('[data-connection-kinds]').forEach(section => {
      section.hidden = !section.dataset.connectionKinds.split(' ').includes(form.elements.kind.value);
    });
  }
  form.elements.kind.addEventListener('change', visibility); visibility();
  function argocdAccessVisibility() {
    const mode = form.elements.access_mode?.value || 'direct';
    document.querySelectorAll('[data-argocd-access-mode]').forEach(field => {
      field.hidden = field.dataset.argocdAccessMode !== mode;
    });
  }
  form.elements.access_mode?.addEventListener('change', argocdAccessVisibility);
  argocdAccessVisibility();
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const data = new FormData(form);
    const lines = name => String(data.get(name) || '').split('\n').map(s => s.trim()).filter(Boolean);
    const button = form.querySelector('[type="submit"]'); button.disabled = true;
    try {
      const result = await post('/api/v1/incident-connections', {
        id: data.get('id') || null, kind: form.elements.kind.value, name: data.get('name'),
        cluster_id: data.get('cluster_id') || null, token: data.get('token') || '', webhook_token: data.get('webhook_token') || '',
        access_mode: data.get('access_mode') || 'direct',
        enabled: data.has('enabled'), namespace: data.get('namespace') || 'openshift-gitops', projects: lines('projects'),
        cluster_aliases: lines('cluster_aliases'), target_cluster_ids: [], destination_names: {},
        url: data.get('url') || '', monitoring_url: data.get('monitoring_url') || '',
        api_prefix: data.has('api_prefix') ? data.get('api_prefix') : '/api/v3', repositories: lines('repositories'),
        custom_ca_pem: data.get('custom_ca_pem') || null,
        ...(form.elements.kind.value === 'cluster' ? {allowed_alerts: lines('allowed_alerts')} : {})
      });
      window.location.assign('/settings/connectors?edit=' + encodeURIComponent(result.id));
    } catch (error) {
      const feedback = document.getElementById('incident-feedback');
      if (feedback) feedback.textContent = error.message;
    } finally { button.disabled = false; }
  });
})();
