# Development

```bash
uv sync --dev
uv run --dev prek install
```

Run hooks and tests:

```bash
uv run --dev prek run -a
uv run --dev pytest
```

`examples/` holds short excerpts of each log format from the testbed dataset;
`examples/README.md` lists what each file should be detected as.

Serve the docs locally:

```bash
uv run --group docs mkdocs serve
```

Preview versioned docs (mike) locally:

```bash
uv run --group docs mike serve
```
