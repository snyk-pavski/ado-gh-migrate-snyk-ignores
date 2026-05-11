# ado-gh-migration

A Python CLI that migrates Snyk Code ignore policies from
Azure-Repos-imported to GitHub-imported targets within the same Snyk org. Snyk
assigns new "asset finding" UUIDs on re-import, so the old ignores stop applying;
this tool replays them against the new UUIDs by matching findings on a stable
signature (title, file, line range, columns).

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env       # then edit to add SNYK_TOKEN (or per-group token)
ado-gh-migration --help
```

## Workflow

Each step below is independent and idempotent. State files accumulate under
`state/<group>/<org>/`. Run `--help` on any subcommand for full flag details.

### 1. Capture the source (ADO) state — *before* the GitHub re-imports

```bash
ado-gh-migration capture --group-id <G> --org-id <O>
```

Pulls every ignore policy, SAST project, target, and issue in the org and
writes them to disk. Read-only against Snyk. Add `--project-id <UUID>` to
scope to a single project for safe testing — it filters policies down to only
those affecting that project.

### 2. Re-import the repos to GitHub — *manual, in the Snyk UI*

Use the Snyk GitHub integration. Wait for all SAST scans to complete. The new
GH-imported projects will have **new** asset finding UUIDs — that's expected;
the migration depends on it.

### 3. Re-run capture — *after* the GitHub re-imports, before mapping

```bash
ado-gh-migration capture --group-id <G> --org-id <O>
```

Same command as step 1. The state directory now holds both the ADO and the
new GitHub targets in one place, distinguished by their integration type.

### 4. Configure the URL mapping — *once, before `map`*

```bash
cp mapping.example.yaml mapping.yaml
# edit:
#  - url_derivation rule (transforms ADO URLs → GitHub URLs in bulk)
#  - per-repo overrides for any repo renamed during the migration
```

### 5. Map ADO URLs to their GitHub counterparts — *after step 4*

```bash
ado-gh-migration map --group-id <G> --org-id <O> --mapping mapping.yaml
```

Offline — reads `targets.json` and the mapping config, writes
`url_mapping.json`. Logs how many targets resolved via override vs
derivation, plus how many remain unmapped (add more overrides for those).

### 6. Verify destination targets exist — *after `map`*

```bash
ado-gh-migration verify --group-id <G> --org-id <O>
```

Offline — looks up each mapped destination URL in `targets.json` and
annotates the mapping with `destination_target_id` + a `verify_status`.
If the status is `destination_target_missing`, either the GitHub re-import
hasn't happened yet for that repo or the mapping URL is wrong.

### 7. Apply (dry-run) — *after `verify`*

```bash
ado-gh-migration apply --group-id <G> --org-id <O>
```

Writes two files:

- `apply_plan.json` — full structured detail of every proposed action.
- `apply_plan.csv` — flat human-review view, sorted with actionable rows
  (`would_create`, `would_patch`) at the top. Open it, share it with
  reviewers, decide whether to proceed.

`--dry-run` and `--live` are mutually exclusive. Without `--live`, dry-run
is the default.

### 8. Apply (live) — *after CSV review and approval*

```bash
ado-gh-migration apply --group-id <G> --org-id <O> --live
```

Prompts for interactive confirmation (skip with `--yes` for automation),
then POSTs new policies and PATCHes project metadata. Per-action outcomes
land in `apply_results.json`. Failed actions include Snyk's full error
response for diagnosis; the run continues past individual failures.

**Re-run `capture` (step 1) between live applies** so the local
breadcrumb idempotency check sees the freshly-created policies and reports
them as `already_migrated` next time. If you forget, Snyk's server-side
dedup returns 409 and the executor records it as `already_exists` — a soft
success, not a failure.

### 9. Report — *any time*

```bash
ado-gh-migration report --group-id <G> --org-id <O>
```

Human-readable summary across capture, map, verify, and apply with counts
of every category and a list of entries needing attention.

### 10. Spot-check in the Snyk UI — *after step 8*

Open one of the GitHub-imported projects, find a migrated finding, and
confirm it shows as ignored with the original reason plus the migration
breadcrumb (`[migrated from azure: …; old-policy-id: …]`).

## Apply plan statuses

| Status | Meaning |
|---|---|
| `would_create` | No conflict; safe to POST a new policy. |
| `already_migrated` | We migrated this exact source policy before (matched our breadcrumb). |
| `already_ignored_in_destination` | An effective org-level ignore already covers this asset. Skipped. |
| `already_ignored_via_higher_scope_policy` | A [group-level Snyk Code Security Policy](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/ignore-issues/consistent-ignores-for-snyk-code#manage-ignores-at-the-group-level-through-snyk-code-security-policies) is ignoring this finding. Skipped. |
| `unmappable` | No destination issue with a matching signature. |

Live execution outcomes: `created`, `patched`, `already_exists` (server-side dedup), `skipped`, `failed`.

## State files (`state/<group>/<org>/`)

- `policies.json`, `projects.json`, `targets.json`, `issues/<project>.json` — capture
- `url_mapping.json`, `verify.json` — map + verify
- `apply_plan.json` + `apply_plan.csv` — dry-run plan (CSV is the human-review view)
- `apply_results.json` — live execution log

## Tests

```bash
pytest -q
```
