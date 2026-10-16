# bd web UI

The bd web UI (Node 22.17 or later): a SvelteKit 3 single-page app built to static files (`build/`) with `@sveltejs/adapter-static`.

```bash
npm install
npm run dev            # dev server
npm run build          # static build into build/
npm run check          # svelte-check, then TypeScript 7
npm run lint           # oxlint
npm run format         # oxfmt (format:check to verify)
```

AI tooling for Svelte (the Svelte MCP server, skills and the `svelte-file-editor` agent) is set up at the repository root: `.mcp.json` and `.claude/`. See AGENTS.md here for the conventions.
