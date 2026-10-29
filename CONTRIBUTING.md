# Contributing to Logreach

## Branches

* `main`: released code only
* `development`: integration branch, target for all PRs
* Feature branches: `feature/<name>`, bugfix branches: `fix/<name>`, created from `development`

## Workflow

1. Open or pick an [issue](https://github.com/ait-testbed/logreach/issues). For a bug, include a short
   sample logfile and the command that shows the problem.
2. Branch from `development`.
3. Set up the dev environment:

   ```bash
   uv sync --dev
   uv run --dev prek install
   ```

4. Make your change, add tests.
5. Run the checks:

   ```bash
   uv run --dev prek run -a
   uv run --dev pytest
   ```

6. Open a PR against `development` and fill in the PR template.

## Releases

See the [release process](https://ait-testbed.github.io/logreach/latest/release/).
