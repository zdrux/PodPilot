# Shared SaaS Shell Design QA

## Comparison setup

- Source visual truth: browser-rendered Incidents page from `codex/incident-dashboard-saas` at `http://127.0.0.1:8766/incidents`.
- Pre-change comparison source: browser-rendered Cluster sign-ins page at `http://127.0.0.1:8766/delegated/connect` before the shared-shell change.
- Implementation screenshots: same-turn Codex in-app browser captures of `/incidents`, `/delegated/connect`, and `/clusters/personal?new=1` after the shared-shell change.
- Deployed implementation: `https://podpilot-ai-ops.apps.sno.192-168-0-200.sslip.io/incidents`; the in-app browser reached the OpenShift OAuth login boundary.
- Viewport and pixels: 718 × 856 CSS pixels and 718 × 856 captured pixels at device pixel ratio 1.
- State: dark theme, authenticated local Investigator fixture, Local SNO available, one active incident, three historical incidents, empty personal-cluster list, and populated cluster sign-in form.
- Density normalization: all visual comparisons used the same in-app browser viewport and 1× density without browser chrome.

## Full-view comparison evidence

The Incidents source and the revised Cluster pages now share the same 224px tablet navigation rail, 30–38px page-title scale, 14px body copy, 38px controls, 28px responsive content gutter, quiet surface palette, 10px panel radius, and one-pixel borders. Switching routes no longer changes the sidebar width, brand sizing, title rhythm, or page origin. Incidents remains visually stable after the shared rules were introduced.

## Focused-region comparison evidence

The Cluster sign-in workflow and personal-cluster form were inspected separately because their long labels and field stacks are not legible in a dashboard-only comparison. Step labels, form controls, consent copy, notice treatment, panel headings, and empty-state copy remain readable and aligned. The navigation accessibility tree retains Ask PodPilot, Clusters, Incidents, recent incidents, appearance choices, and identity. No new assets were introduced.

## Required fidelity surfaces

- Fonts and typography: every route inherits the same Inter/system-sans stack, 14px base size, 13px navigation, 30–38px H1 range, 17px panel headings, and 12px controls. Existing dense evidence and chat typography remains intentionally specialized.
- Spacing and layout rhythm: desktop uses a 260px rail and 40px/clamped page gutters; the tested tablet viewport uses a 224px rail and 28px/18px content gutters. Panels use a consistent 16px grid gap and 10px radius.
- Colors and visual tokens: the implementation reuses existing semantic theme variables across dark, classic, light, medium-light, and CIBC Red modes. No route-specific color palette was added.
- Image quality and asset fidelity: the existing PodPilot mark and theme icons are unchanged. This interface contains no illustrative raster assets, and no placeholder or generated imagery was added.
- Copy and content: operational labels, cluster/OAuth warnings, incident state, evidence counts, timestamps, configuration fields, and role information are unchanged.

## Comparison history

1. P1 — Route changes altered the shell geometry and typography because the SaaS rules were scoped only to `.incident-dashboard-page`. The shared `saas-app` shell now owns the rail, brand, navigation, type scale, page gutters, controls, and panel surfaces. Post-fix comparison shows the Incidents and Cluster routes beginning on identical columns and baselines.
2. P2 — Existing Quiet Ledger grid rules removed card gaps and side borders on non-Incidents pages. Later shared-shell rules restore 16px grid gaps and complete one-pixel panel boundaries. The personal-cluster capture confirms distinct list and form work areas.
3. P2 — The global 720px rule previously hid navigation on non-Incidents routes. The shared responsive rule now keeps all navigation and identity controls visible through 641px, matching the corrected Incidents behavior.

## Findings

No actionable P0, P1, or P2 findings remain in the tested routes and viewport. Ask retains its purpose-built full-height conversation canvas while using the same outer navigation geometry and typography. A dedicated compact mobile navigation below 640px remains optional P3 work.

## Verification

- Browser: paired before/after Cluster comparison; Incidents stability check; personal-cluster form check; sidebar route and theme controls remained available.
- Automated: all 805 model-free tests passed.
- SNO: builds `podpilot-132` and `podpilot-oc-runner-14` completed; deployment has one available replica; API container is ready with zero restarts.
- Deployed artifact: the running API container contains the shared SaaS CSS marker, `saas-app` body class, and `saas-shell-32` cache key.
- Source hygiene: `git diff --check` passed before commit.

## Final result

final result: passed
