# docs/assets

Terminal GIFs referenced from the README, with the asciinema casts they are rendered from under [src/](src/). Build with `make -C docs/assets` (see the [Makefile](Makefile) for the exact asciinema, agg and gifsicle flags; `run.cast` is recorded at 110x17, the other two at 110x30).

| cast | GIFs | shows |
|---|---|---|
| `src/run.cast` | `run-dark.gif`, `run-light.gif` | `uv run dea run tests/fixtures/idea.yml --splunk real --window=-24h --model ... -v` against the test Splunk droplet (Splunk Enterprise 10.6.1.1) with real inference: one `-v` line per state transition, idle time collapsed, ending in `done  tunes=1 remakes=0 reviews=1 cost_usd=0.60` and the two output paths; 3 minutes 56 seconds of wall clock |
| `src/ideas.cast` | `ideas-dark.gif`, `ideas-light.gif` | `uv run dea ideas tests/fixtures/article.html -o ideas/ && head -22 ideas/office_*.yml`: the written idea paths, then the head of the office-macro idea YAML |
| `src/publish.cast` | `publish-dark.gif`, `publish-light.gif` | `uv run dea publish docs/examples/office_app_spawns_encoded_powershell/detection.yml --dry-run`: the macro stanza and the saved-search properties |

Rules:

- A GIF is a recording of the real command; nothing is mocked or typed in after the fact. `src/typed.sh` prints the prompt, types the command and then runs it, so the command shown is the command executed.
- The run GIF is recorded against the real test Splunk (`.env.local`, sourced inside the recorded command and never shown) with real inference, and its README caption says so. The Splunk host and token do not appear in the cast.
- The README uses the dark and light variants through a `<picture>` element; the docs pages embed no GIFs.
- All six GIFs are rendered and referenced. If one is re-recorded and not yet rendered, keep the `<picture>` with its alt text, which GitHub shows in place of a missing file, and run `make -C docs/assets` before committing.
- `*.raw.gif` are intermediates and git-ignored; the `.cast` files are committed.
- The casts are recorded with `-i 1.5` (idle capped at record time); agg caps idle again at 1 s and plays at 1.25x, so a 5-10 minute run renders in well under a minute while every transition line stays visible.
