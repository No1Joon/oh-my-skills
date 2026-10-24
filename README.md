# oh-my-skills

Personal Claude Code skills, published as a plugin marketplace. Skills are grouped into plugins by domain, so you install only the groups you need.

## Install

```bash
# Register the marketplace
/plugin marketplace add No1Joon/oh-my-skills

# Install a plugin
/plugin install security@oh-my-skills
```

From a shell, use `claude plugin marketplace add No1Joon/oh-my-skills` and `claude plugin install security@oh-my-skills`.

Skills inside a plugin are namespaced by the plugin name, e.g. `/security:php-security-hardening`.

## Plugins

| Plugin | Skills | Description |
|---|---|---|
| `security` | `php-security-hardening` | Diagnose and patch PHP vulnerabilities across code, runtime and server config; region-specific platform playbooks; emergency response for runtime flaws such as PHP2Shell |

## Layout

```
oh-my-skills/
├── .claude-plugin/
│   └── marketplace.json          # lists every plugin in this repo
└── plugins/
    └── <plugin>/
        ├── .claude-plugin/
        │   └── plugin.json       # name must match the marketplace entry
        └── skills/
            └── <skill>/
                ├── SKILL.md      # workflow and rules, loaded on trigger
                └── references/   # detail loaded only when a step needs it
```

## Adding a skill

1. Pick the plugin by domain, or create `plugins/<new-plugin>/` with its own `.claude-plugin/plugin.json`.
2. Add `skills/<skill-name>/SKILL.md` with `name` and `description` frontmatter. Keep long tables and dated material in `references/`.
3. For a new plugin, add an entry to `.claude-plugin/marketplace.json` whose `name` equals the plugin's `plugin.json` name.
4. Bump `version` in the plugin's `plugin.json` so installed copies update.
5. Validate before pushing:
   ```bash
   claude plugin validate .
   claude plugin validate ./plugins/<plugin>
   ```

Plugin names must not start with `claude-` or `anthropic-`.

## Security skill notes

`php-security-hardening` is defensive only: it does not produce exploit code, and it scans only systems you own or administer. Advisory files under `references/advisories/` are dated snapshots; re-verify against official advisories before acting.
