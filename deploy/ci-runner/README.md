# Optional self-hosted CI runners

`ci.yml` runs where the repository variable `AMX_CI_RUNS_ON` says. When the
variable is unset, jobs use GitHub-hosted `ubuntu-24.04`. Set it to
`["self-hosted","amx-ci"]` to use the runners defined here instead:

```bash
gh variable set AMX_CI_RUNS_ON -R <owner>/<repo> --body '["self-hosted","amx-ci"]'
gh variable delete AMX_CI_RUNS_ON -R <owner>/<repo>   # back to hosted
```

Hosted runners are the default; self-hosting is optional. Never allow untrusted
fork pull requests onto privileged self-hosted runners. Configure workflow
approval and isolate runners from production hosts, mail, credentials and data.

## Start runners

```bash
AMX_CI_REPO=<owner>/<repo> deploy/ci-runner/up.sh 3
```

This builds `amx-ci-runner:local` and starts `amx-ci-runner-1..3`. Each one is
a privileged container with its own Docker daemon and its own
`amx-ci-runner-N-docker` volume. A job's compose stacks and the suite lock
therefore stay inside one runner, and nothing else on the host Docker daemon
can collide with the suite's fixed `amx` project. Three runners let the
Postfix and Stalwart suites run in parallel, as they do on hosted runners.

The runners restart with the host's Docker daemon (`--restart unless-stopped`)
and keep their registration in the container. Recreating a container
re-registers it with a fresh token.

## Stop runners

```bash
for n in 1 2 3; do docker rm -f amx-ci-runner-$n; docker volume rm amx-ci-runner-$n-docker; done
```

Then delete the offline runners under the repo's Settings, Actions, Runners,
or with `gh api -X DELETE repos/<owner>/<repo>/actions/runners/<id>`.
