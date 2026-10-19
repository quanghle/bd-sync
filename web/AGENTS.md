## Project Configuration

- **Framework**: SvelteKit 3 (Svelte 5 runes), `@sveltejs/adapter-static` as a single-page app (`ssr = false`, fallback `index.html`); `npm run build` writes `build/`
- **Language**: TypeScript 7 (`@typescript/native` = `npm:typescript@^7`; `npm run typecheck`) checks the `.ts` files. `typescript` is aliased to `@typescript/typescript6` because svelte-check needs the 6.x JS API, so `.svelte` files are type-checked by svelte-check on TypeScript 6
- **Lint / format**: oxlint (`npm run lint`, `.oxlintrc.json`) and oxfmt (`npm run format`, `npm run format:check`, `.oxfmtrc.json`, `.svelte` files through its `svelte` option); no ESLint or Prettier. SvelteKit's types (through vite's) make the Node types visible to the typecheck of `src/`, so a `no-restricted-globals` override for `src/**` in `.oxlintrc.json` is what keeps Node-only globals (`process`, `Buffer`, `require`, ...) out of the browser code
- **Checks**: `npm run check` (svelte-check, then tsc 7), `npm run lint`, `npm run format:check`, `npm run build`
- **Package manager**: npm
- **AI tooling**: the local Svelte MCP server is registered in the repository root's `.mcp.json`; the `svelte-file-editor` agent lives in the root `.claude/agents/`, and the Svelte skills are published from the root `.bd/source/agents/claude/skills/` and reach `.claude/skills/` when `bd agents approve` runs; the Svelte language server comes from the `svelte-lsp` plugin of the project-local marketplace `bd-web` (`web/.claude-plugin/marketplace.json`, `web/claude-plugins/svelte-lsp/`), enabled in the root `.claude/settings.json`, and started with `node` from `web/node_modules` (the locked `svelte-language-server` devDependency, so `npm ci` first); the plugin has no version, so it follows the checkout

---

You are able to use the Svelte MCP server, where you have access to comprehensive Svelte 5 and SvelteKit documentation. Here's how to use the available tools effectively:

## Available Svelte MCP Tools:

### 1. list-sections

Use this FIRST to discover all available documentation sections. Returns a structured list with titles, use_cases, and paths.
When asked about Svelte or SvelteKit topics, ALWAYS use this tool at the start of the chat to find relevant sections.

### 2. get-documentation

Retrieves full documentation content for specific sections. Accepts single or multiple sections.
After calling the list-sections tool, you MUST analyze the returned documentation sections (especially the use_cases field) and then use the get-documentation tool to fetch ALL documentation sections that are relevant for the user's task.

### 3. svelte-autofixer

Analyzes Svelte code and returns issues and suggestions.
You MUST use this tool whenever writing Svelte code before sending it to the user. Keep calling it until no issues or suggestions are returned.

### 4. playground-link

Generates a Svelte Playground link with the provided code.
After completing the code, ask the user if they want a playground link. Only call this tool after user confirmation and NEVER if code was written to files in their project.
