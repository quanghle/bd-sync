# bd web UI

The bd web UI (Node 26 or later): a SvelteKit 3 single-page app built to static files (`build/`) with `@sveltejs/adapter-static`.

```bash
npm ci                 # install exactly the lockfile
npm run dev            # dev server
npm run build          # static build into build/
npm run check          # svelte-check, then TypeScript 7
npm run lint           # oxlint
npm run format         # oxfmt (format:check to verify)
```

AI tooling for Svelte (the Svelte MCP server, skills and the `svelte-file-editor` agent) is set up at the repository root: `.mcp.json` and `.claude/`. The Svelte language server reaches Claude Code through the `svelte-lsp` plugin in this directory's marketplace (`.claude-plugin/marketplace.json`, `claude-plugins/svelte-lsp/`), which the root `.claude/settings.json` declares and enables: start Claude Code at the repository root and accept the marketplace when asked (or `/plugin install svelte-lsp@bd-web`). See AGENTS.md here for the conventions.

Files under `web/` are checked out with LF line endings (`.gitattributes`), which oxfmt expects. A Windows checkout made before that file existed keeps CRLF until its files are rewritten: in `web/`, run `git rm --cached -r -q . && git reset --hard` once (it discards uncommitted changes under `web/`).
