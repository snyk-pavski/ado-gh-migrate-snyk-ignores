"""ado-gh-migration CLI entry point — wires the five stages."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import typer

from .stages.apply import build_plan, execute_plan
from .stages.capture import capture_org
from .stages.map import map_org
from .stages.report import report_org
from .stages.verify import verify_org

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Migrate Snyk Code ignore policies + project metadata from ADO-imported targets to GitHub-imported targets within the same Snyk org.",
)


@app.callback()
def main(
    log_level: str = typer.Option(
        "INFO", "--log-level", help="Logging level: DEBUG | INFO | WARNING | ERROR"
    ),
):
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
        stream=sys.stderr,
    )


_GROUP_OPT = typer.Option(..., "--group-id", help="Snyk Group UUID (used to resolve the per-group token).")
_ORG_OPT = typer.Option(..., "--org-id", help="Snyk Org UUID hosting both the ADO and GitHub targets.")
_STATE_OPT = typer.Option(None, "--state-dir", envvar="STATE_DIR", help="State directory root. Defaults to ./state.")


@app.command()
def capture(
    group_id: str = _GROUP_OPT,
    org_id: str = _ORG_OPT,
    project_id: str = typer.Option(
        None,
        "--project-id",
        help="Optional. Scope project + target + issues capture (and filter policies) to a single project for safe testing.",
    ),
    region: str = typer.Option("us", "--region", help="Snyk region: us | eu | au"),
    api_version: str = typer.Option(None, "--api-version", envvar="SNYK_REST_API_VERSION"),
    state_root: Path = _STATE_OPT,
):
    """Capture stage: pull policies + projects + targets + issues for the org. Captures both ADO and GitHub targets in one go."""
    summary = capture_org(
        group_id=group_id,
        org_id=org_id,
        region=region,
        api_version=api_version,
        state_root=state_root,
        project_id=project_id,
    )
    typer.echo("\nCapture summary:")
    typer.echo(json.dumps(summary, indent=2, default=str))


@app.command("map")
def map_cmd(
    group_id: str = _GROUP_OPT,
    org_id: str = _ORG_OPT,
    mapping: Path = typer.Option(..., "--mapping", help="Path to mapping.yaml."),
    state_root: Path = _STATE_OPT,
):
    """Map stage: walk captured ADO targets, apply URL resolver, write url_mapping.json."""
    output = map_org(
        group_id=group_id,
        org_id=org_id,
        mapping_path=mapping,
        state_root=state_root,
    )
    typer.echo("\nMap counts:")
    typer.echo(json.dumps(output.get("counts"), indent=2))


@app.command()
def verify(
    group_id: str = _GROUP_OPT,
    org_id: str = _ORG_OPT,
    state_root: Path = _STATE_OPT,
):
    """Verify stage: confirm GH-imported destination targets exist in the same org for each mapped ADO entry."""
    output = verify_org(group_id=group_id, org_id=org_id, state_root=state_root)
    typer.echo("\nVerify counts:")
    typer.echo(json.dumps(output.get("verify_counts"), indent=2))


@app.command()
def apply(
    group_id: str = _GROUP_OPT,
    org_id: str = _ORG_OPT,
    state_root: Path = _STATE_OPT,
    live: bool = typer.Option(
        False,
        "--live",
        help="Actually POST/PATCH against Snyk. Without this flag, only writes apply_plan.json + apply_plan.csv (dry-run).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Explicitly request dry-run mode. Mutually exclusive with --live. Same effect as omitting --live; useful in scripts to be unambiguous.",
    ),
    region: str = typer.Option("us", "--region", help="Snyk region for live writes."),
    api_version: str = typer.Option(
        None, "--api-version", envvar="SNYK_REST_API_VERSION", help="Snyk REST API version for live writes."
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the interactive confirmation when --live is passed (for automation).",
    ),
):
    """Apply stage: dry-run by default; --live to actually POST/PATCH against Snyk.

    Always writes apply_plan.json + apply_plan.csv first. The CSV is sorted with
    actionable rows (would_create / would_patch) at the top — review it before
    re-running with --live.
    """
    if live and dry_run:
        typer.secho(
            "error: --live and --dry-run are mutually exclusive", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(2)

    plan = build_plan(group_id=group_id, org_id=org_id, state_root=state_root)
    plan_csv = (state_root or Path("./state")) / group_id / org_id / "apply_plan.csv"
    typer.echo("\nApply plan summary:")
    typer.echo(json.dumps(plan.get("summary"), indent=2))
    typer.echo(f"\nReview-friendly CSV: {plan_csv.resolve()}")

    if not live:
        return

    if not yes:
        confirmed = typer.confirm(
            f"\nLive execution will POST/PATCH against Snyk org {org_id} "
            f"(region={region}). Proceed?",
            default=False,
        )
        if not confirmed:
            typer.echo("aborted; no writes performed.")
            raise typer.Exit(0)

    results = execute_plan(
        plan=plan,
        group_id=group_id,
        org_id=org_id,
        region=region,
        api_version=api_version,
        state_root=state_root,
    )
    typer.echo("\nLive execution results:")
    typer.echo(json.dumps(results.get("summary"), indent=2))


@app.command()
def report(
    group_id: str = _GROUP_OPT,
    org_id: str = _ORG_OPT,
    state_root: Path = _STATE_OPT,
):
    """Report stage: human-readable summary of capture + map + verify + apply."""
    text = report_org(group_id=group_id, org_id=org_id, state_root=state_root)
    typer.echo(text)


if __name__ == "__main__":
    app()
