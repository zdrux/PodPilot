# Personal GitHub Copilot proof of concept

Configuration administrators can link their GitHub Copilot account, discover the
models available to that account, and select one for a read-only Ask investigation.
OpenShift OAuth proxy authentication remains mandatory. Membership in the runtime
ConfigMap's `configuration_admin_groups` grants this feature independently of
Read-Write or Breakglass roles. An empty group list grants nobody access.

## Enable in OpenShift

1. Register a GitHub OAuth App (or GitHub App with user authorization) approved
   by the corporate organization. Set its callback URL to
   `https://<podpilot-route>/api/v1/copilot/callback`. Enable expiring user tokens;
   PodPilot requests `offline_access` and handles refresh-token rotation. Corporate
   OAuth-app restrictions, SSO, subscription entitlement and model policy still apply.
2. Put the public client ID in `podpilot-runtime.data.copilot_client_id` and the
   exact callback URL in `copilot_redirect_uri`. Store the client secret in a
   separately provisioned `podpilot-copilot-oauth` Secret, key `client_secret`.
   Do not put the client secret in the ConfigMap, repository or shell history.
3. Apply the workload manifests, run Alembic through migration
   `0031_personal_copilot`, and roll out the new image. The deployment optionally
   references the OAuth Secret so installations without Copilot keep working.
   The workload creates an empty `podpilot-copilot-credentials` Secret and a
   resourceName-restricted Role granting the runtime get/patch/update on that
   Secret only. It does not grant any additional cluster operations.
4. Sign into PodPilot through the OpenShift proxy as a configuration administrator.
   Open **Personal Copilot**, connect GitHub, then **Refresh available models**.
   Choose a model there or in the new Ask composer, sign into the selected
   clusters through the existing delegated flow, and submit an investigation.
   A conversation retains its model choice; choose a different model in a new chat.

No shared model profile is required for a personal Copilot investigation. Shared
provider profiles and unattended incident investigations retain their existing
behavior. Personal Copilot requires `delegated_access_enabled=true` and cannot
be selected for Action mode or unattended incident jobs.

## Configuration and token lifecycle

Runtime settings use the standard `PODPILOT_` environment prefix. Workload
ConfigMap changes require a rollout because settings are read at process start.

| ConfigMap key | Default | Purpose |
| --- | --- | --- |
| `copilot_client_id` | empty | GitHub OAuth client ID; empty disables connection setup |
| `copilot_redirect_uri` | empty | Public HTTPS callback URL; query strings/fragments are rejected |
| `copilot_connection_lifetime_seconds` | `2592000` | Absolute connection lifetime: 30 days; supported range one hour to 180 days |
| `copilot_credential_store` | `kubernetes` in workload manifests | Persistent Secret storage; `memory` is for local development/tests |
| `copilot_secret_namespace` | `ai-ops` | Namespace of the dedicated personal credential Secret |
| `copilot_secret_name` | `podpilot-copilot-credentials` | Precreated Secret used for personal credentials |

OpenShift packaging selects `PODPILOT_COPILOT_CREDENTIAL_STORE=kubernetes`.
Local development defaults to `memory`; this mode loses connections on restart
and is clearly labeled in personal settings.

The dedicated Secret holds one owner-keyed JSON entry containing the access token,
optional refresh token, GitHub login, creation/expiry times and model catalog.
The key is derived from the authenticated OpenShift username; request parameters
and browser cookies cannot select another user's credentials. The database holds
only the non-secret owner key and selected model on a conversation. GitHub tokens
are never returned to the browser or put into prompts, evidence, audit details or
the database. Kubernetes Secret storage uses the cluster's existing RBAC and
encryption-at-rest configuration; base64 encoding itself is not encryption.

PodPilot renews access tokens within 60 seconds of GitHub expiry when a valid
refresh token is available. It stores both replacement tokens before continuing.
Refresh does not extend the configured absolute connection lifetime. Shortening
the configured lifetime also shortens existing connections after the next rollout;
increasing it does not extend the expiry already recorded at connection time.
An expired connection is denied and its Secret entry removed on next access.
Provider revocation or corporate policy can require reconnection earlier.
Disconnect deletes the stored credentials and pending OAuth state. It does not
revoke the GitHub app grant; users can revoke that separately in GitHub settings.

## Trust and execution boundaries

OAuth uses a ten-minute, single-use server-side state bound to the OpenShift
identity and an HttpOnly SameSite=Lax browser binding cookie, plus PKCE S256.
Connect, model refresh and disconnect require existing PodPilot CSRF protection.
The callback still passes through OpenShift proxy authentication. A restart
invalidates unfinished OAuth flows, but Secret-backed completed connections survive.

The adapter uses pinned Python SDK `github-copilot-sdk==1.0.35` and its pinned
runtime `1.0.112`. The image downloads the verified runtime bundle and native
library at build time, then disables automatic runtime downloads. Runtime model
traffic uses validated HTTPS; no TLS bypass is offered. For local development,
run `python -m copilot download-runtime --in-process` before first use. Windows
Store Python users may need `COPILOT_CLI_EXTRACT_DIR` set to a normal writable
directory outside the Store's virtualized application-data cache.

Each model request starts a separate empty-mode SDK process in a temporary
directory, with an explicit user token and no shared CLI login, inherited
credentials, repository, plugins, MCP servers or available execution tools.
All permission requests are rejected. SDK configuration discovery, session
storage, file hooks, skills and host Git operations are disabled. Raw SDK error
logging is suppressed at the adapter boundary; operator errors and audit events
are sanitized. Temporary runtime files are removed after the process stops.

Copilot receives PodPilot's bounded/redacted conversation and the existing tool
schemas. It returns a structured proposal of at most one tool call. PodPilot's
existing agent loop validates that proposal, records evidence and sends reads
through the user's delegated read-only broker capability. Copilot has no direct
cluster credentials or execution access. PodPilot's finalization and isolated log
specialists reuse the same transport and existing schema validation. Provider
input budgets and runtime output/deadline limits remain bounded. Token usage is
not currently reported by this adapter in the model-usage panel.

Group capability is checked on HTTP entry, queueing, worker execution and each
model request, using the existing OpenShift role cache. Discovery omits models
marked disabled by GitHub; GitHub enforces current policy when a request runs.
Authorization, discovery, refresh, expiry and disconnect have credential-free
audit events. Disconnect prevents subsequent model requests and discards in-flight
model responses after completion; it cannot retract data already sent upstream.

## Validation and limits

Model-free tests cover proxy/CSRF/admin access, OAuth owner/browser binding and
replay, persisted credentials across service restart, token rotation and absolute
expiry, disabled-model filtering, unavailable models, SDK tool denial and cleanup,
Action rejection, and a complete mocked Copilot read through the existing
delegated runner. No real subscription or provider response quality is asserted.

This PoC supports one API replica. Refresh-token rotation is serialized in-process;
multiple replicas require distributed refresh coordination before deployment.
The credential Secret also has Kubernetes' object-size limit; this is intended
for a small configuration-administrator cohort. A live corporate OAuth round-trip,
model discovery and read-only investigation must pass before enabling this in an
environment. No credentials or live GitHub authorization are bundled.

Provider references: [SDK OAuth setup](https://docs.github.com/en/copilot/how-tos/copilot-sdk/setup/github-oauth),
[OAuth token practices](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/best-practices-for-creating-an-oauth-app),
[refreshing GitHub user tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens).
