# wyrm AI skill

Teach your AI assistant to use wyrm and the OTM format — so it can generate threat
models from your infrastructure, interpret STRIDE findings, and fix them by adding
real controls. One shared body of knowledge, packaged for three assistants.

| File | For |
|---|---|
| [`SKILL.md`](SKILL.md) | Claude (Agent Skill) |
| [`copilot-instructions.md`](copilot-instructions.md) | GitHub Copilot |
| [`chatgpt-instructions.md`](chatgpt-instructions.md) | ChatGPT (Custom GPT) |

## Install

### Claude (Agent Skill)

Claude Code / Claude apps that support Agent Skills load a skill from a folder
containing `SKILL.md`.

```sh
# Claude Code: drop it in your skills directory
mkdir -p ~/.claude/skills/wyrm-threat-modeling
cp SKILL.md ~/.claude/skills/wyrm-threat-modeling/
```

Or copy `skill/` into a plugin's skills folder. The `description` in the
frontmatter is what Claude uses to decide when to apply it. In claude.ai you can
also paste `SKILL.md` into a Project's custom instructions.

### GitHub Copilot

Copilot reads repository custom instructions from `.github/copilot-instructions.md`:

```sh
mkdir -p .github
cp copilot-instructions.md .github/copilot-instructions.md
```

Now Copilot Chat in that repo knows how to work with wyrm. (You can also paste the
file into a Copilot chat ad hoc.)

### ChatGPT

Create a **Custom GPT** (chat.openai.com → Explore GPTs → Create) and paste
`chatgpt-instructions.md` into its Instructions. For deeper answers, attach this
repo's `SKILL.md` and `docs/DETECTION.md` as Knowledge files.

## What it enables

- "Generate a threat model from our `docker-compose.yml`" → the assistant runs
  `wyrm init`, reviews the baseline, and adds asset sensitivity.
- "wyrm flags WYRM-T001 on the login flow — fix it" → it explains the risk and
  edits the model (e.g. enforces + tags TLS).
- "Add a Cloudflare WAF mitigation" → it adds a `mitigation` and wires it in.
- "Is this model CI-ready?" → it runs `wyrm analyze --fail-on high` and resolves
  what's left.

The assistant works on the same `.threatmodel/*.otm.yaml` files as the CLI, LSP,
and editor plugins — everything stays in sync.
