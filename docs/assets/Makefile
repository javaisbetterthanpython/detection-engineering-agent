# Terminal GIFs for the README and docs, rebuilt from committed asciinema casts in src/.
#
#   brew install asciinema agg gifsicle          # ffmpeg is not needed
#   make -C docs/assets                          # every src/*.cast -> <name>-dark.gif + <name>-light.gif
#   make -C docs/assets record-publish           # re-record one cast (runs the real command)
#
# Casts are text and small: commit them so anyone can re-render. *.raw.gif are intermediates (git-ignored).
# src/typed.sh prints a prompt, types the command and then runs it, so a cast shows the exact command it
# executes; nothing is typed in after the fact. Recording runs from the repo root with the home directory
# hidden. record-run sources .env.local inside the recorded command (never on screen) and runs against the
# real Splunk; the host and token are never printed. Size target under 4 MB per GIF.

CASTS   := run ideas publish
GIFS    := $(foreach c,$(CASTS),$(c)-dark.gif $(c)-light.gif)
AGG     := agg --font-size 16 --speed 1.25 --idle-time-limit 1 --fps-cap 20 --last-frame-duration 3
GIFSICLE:= gifsicle -O3 --lossy=80 --colors 128
REC     := asciinema rec --headless -i 1.5 --overwrite
REC_run     := $(REC) --window-size 110x17
REC_ideas   := $(REC) --window-size 110x30
REC_publish := $(REC) --window-size 110x30
TYPED   := docs/assets/src/typed.sh

# the command each cast records, run from the repo root
CMD_run     := uv run dea run tests/fixtures/idea.yml --splunk real --window=-24h --model author=claude-opus-4-8 --model review=claude-opus-4-8 --model refine=claude-opus-4-8 --max-cost 5 -v
CMD_ideas   := uv run dea ideas tests/fixtures/article.html -o ideas/ && head -22 ideas/office_*.yml
CMD_publish := uv run dea publish docs/examples/office_app_spawns_encoded_powershell/detection.yml --dry-run

.PHONY: all clean $(addprefix record-,$(CASTS))
all: $(GIFS)

%-dark.raw.gif: src/%.cast
	$(AGG) --theme github-dark $< $@

%-light.raw.gif: src/%.cast
	$(AGG) --theme github-light $< $@

%.gif: %.raw.gif
	$(GIFSICLE) -o $@ $<

record-run:
	cd ../.. && $(REC_run) -c "bash -c 'set -a; . .env.local; set +a; exec $(TYPED) \"$(CMD_run)\"'" docs/assets/src/run.cast

record-ideas:
	cd ../.. && rm -rf ideas && $(REC_ideas) -c "$(TYPED) '$(CMD_ideas)'" docs/assets/src/ideas.cast

record-publish:
	cd ../.. && env -u SPLUNK_TOKEN -u SPLUNK_HOST $(REC_publish) -c "$(TYPED) '$(CMD_publish)'" docs/assets/src/publish.cast

clean:
	rm -f *.raw.gif
