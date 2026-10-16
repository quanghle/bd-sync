# bd web UI

The bd web UI (Node 26 or later): a SvelteKit 3 single-page app built to static files (`build/`) with `@sveltejs/adapter-static`.

```bash
npm ci                 # install exactly the lockfile (also the Svelte language server)
npm run dev            # dev server
npm run build          # static build into build/
npm run check          # svelte-check, then TypeScript 7
npm run lint           # oxlint
npm run format         # oxfmt (format:check to verify)
```

AI tooling for Svelte (the Svelte MCP server, skills and the `svelte-file-editor` agent) is set up at the repository root: `.mcp.json` and `.claude/`. The Svelte language server reaches Claude Code through the `svelte-lsp` plugin in this directory's marketplace (`.claude-plugin/marketplace.json`, `claude-plugins/svelte-lsp/`), which the root `.claude/settings.json` declares and enables: start Claude Code at the repository root and accept the marketplace when asked. Keep it a project plugin: installed for the user (`/plugin install` without `--scope project`), it would start in other projects, where `${CLAUDE_PROJECT_DIR}/web/node_modules` does not exist. The plugin starts this directory's own `svelte-language-server`, an exact devDependency locked by `package-lock.json`, with `node` from `node_modules/`, found through `${CLAUDE_PROJECT_DIR}`: run `npm ci` here first, or the server fails to start with node's `Cannot find module` in Claude Code's debug log. The plugin has no version, so edits to it reach installs from the checkout. See AGENTS.md here for the conventions.

Files under `web/` are checked out with LF line endings (`.gitattributes`), which oxfmt expects. A Windows checkout made before that file existed keeps CRLF until its files are rewritten: in `web/`, run `git rm --cached -r -q . && git reset --hard` once (it discards uncommitted changes under `web/`).
