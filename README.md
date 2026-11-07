# drifter

Detects and classifies infrastructure drift in Terraform and OpenTofu projects. It runs a read-only plan against live infrastructure and reports each changed resource as one of:

- **out-of-band**: live infrastructure changed outside IaC since the last apply (console edits, scripts, other tools). Comes from the plan's `resource_drift`.
- **unapplied**: the `.tf` code differs from live infrastructure but nobody applied it. Comes from `resource_changes`.

Each resource is also tagged `added`, `modified`, `destroyed`, or `replaced`.

## Install

```sh
make build        # → bin/drifter
```

You need `terraform` or `tofu` on `PATH`, unless you pass `--plan-file`.

## Usage

```sh
drifter scan                          # current directory
drifter scan ./envs -r -p 8           # discover root modules, 8 plans in parallel
drifter scan --json > drift.json      # CI payload
drifter scan --plan-file plan.json    # analyse an existing `terraform show -json`

drifter diff aws_security_group.web   # attribute-level detail
drifter diff 'module.network.*' -w envs/prod

drifter ignore aws_autoscaling_group.web --attr desired_capacity
drifter ignore '*' --attr tags_all --reason "provider default_tags"
drifter ignore --list

drifter report > drift.md             # PR comment (GitHub/GitLab markdown)
drifter report --json -o drift.json
```

Exit codes follow `terraform plan -detailed-exitcode`: `0` means no drift, `1` means an error, `2` means drift. Pass `--exit-zero` to make `scan` always exit 0 on success. `report --fail-on-drift` exits 2 when the report contains drift.

`scan` stores redacted results in `.drifter/last-scan.json` (mode 0600). `diff` and `report` read that file and re-apply the current `.drifterignore`, so a new ignore rule takes effect without a rescan.

### .drifterignore

```
# whole resource
module.monitoring.*
# one attribute and everything nested under it
aws_autoscaling_group.*:desired_capacity
*:tags_all
```

`*` matches any run of characters. Everything else is literal, so addresses such as `aws_instance.web["a"]` need no escaping.

## Side effects and secrets

- Plans run with `-lock=false -input=false` and never take a state lock. The binary plan file goes to a private (0700) temp directory, which is removed as soon as `show -json` has read it.
- When a module has no `.terraform` directory, drifter runs `init` into a temporary `TF_DATA_DIR`, so your checkout stays untouched. Pass `--no-init` to fail instead. `init` may still create `.terraform.lock.hcl` if the module has none.
- `TF_LOG*` and `TF_CLI_ARGS*` are removed from the child environment, so debug logs can't capture credentials and injected flags can't change the plan.
- Before anything is printed or cached, the following are masked or scrubbed:
  - values the provider marks sensitive, plus digests of them (`content_sha256`, `etag`, ...) and any attribute sharing a digest's value, which providers often leave unmarked
  - attributes whose names look like secrets (`password`, `token`, ...)
  - known secret formats: AWS keys, PEM keys, GitHub, GitLab and Slack tokens, JWTs, URL credentials
  - the literal values of secret-looking environment variables

## Layout

```
cmd/drifter/            entrypoint
internal/cli/           cobra commands, cache, exit codes
pkg/engine/             Drift Engine: classification, attribute diffs, ignore application
pkg/provider/           StateProvider interface + FileProvider
pkg/provider/tfcli/     StateProvider backed by the terraform/tofu binary
pkg/tfplan/             `show -json` plan types
pkg/hclcheck/           native HCL/JSON parsing: syntax errors, root module discovery
pkg/ignore/             .drifterignore parsing and matching
pkg/redact/             secret scrubbing
pkg/render/             terminal, markdown, and JSON output
pkg/drifterr/           typed user-facing errors with hints
```

The engine and everything else under `pkg/` does no terminal or filesystem I/O of its own. A multi-tenant worker can use it this way:

```go
eng := &engine.Engine{
    Provider: myProvider,                 // implements provider.StateProvider
    Rules:    rules,                      // ignore.Parse(tenantConfig)
    Scrubber: redact.New(tenantSecrets...),
    Parallelism: 4,
}
report, err := eng.Scan(ctx, targets)
render.Markdown(w, report, render.MarkdownOptions{})
```

If you already have plan JSON, call `eng.Analyze(plan)` directly.

## License

MIT. See [LICENSE](LICENSE).
