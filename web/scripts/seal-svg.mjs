// Renders the page's wax seal to a standalone SVG, for the README.
//   npm run seal-svg            (writes ../docs/assets/seal.svg)
// The image follows the viewer's light or dark theme, like the page.
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(root, process.argv[2] ?? "../docs/assets/seal.svg");

// The seal's colours and the few rules it needs, from src/styles.css.
const STYLE = `
svg { --line: #d4cedf; --wax: #8c1c3c; --wax-hi: #c24a6c; --wax-lo: #4b0c21; --brass: #a87a22; --brass-hi: #e0b458; }
@media (prefers-color-scheme: dark) {
  svg { --line: #2e2842; --wax: #9e2446; --wax-hi: #d25b7d; --wax-lo: #4a0c21; --brass: #d2a54a; --brass-hi: #f0cd7a; }
}
.ring-ticks, .ring-lit { fill: none; stroke-width: 11; stroke-dasharray: 1.4 6.35; }
.ring-ticks { stroke: var(--line); }
.ring-lit { stroke: var(--brass); }
.ring-mask { fill: none; stroke: #fff; stroke-width: 18; }
.ring-head { transform-box: view-box; transform-origin: 50% 50%; }
.ring-head circle { fill: var(--brass-hi); filter: drop-shadow(0 0 5px var(--brass-hi)); }
.spill, .bit { opacity: 0; }
`;

const server = await createServer({ root, logLevel: "error", appType: "custom", server: { middlewareMode: true } });
try {
  const { Seal } = await server.ssrLoadModule("/src/Seal.tsx");
  const { Phase } = await server.ssrLoadModule("/src/phase.ts");
  const figure = renderToStaticMarkup(createElement(Seal, { phase: Phase.Open, fill: 0.64, still: true }));
  const svg = figure
    .replace(/^<figure[^>]*>/, "")
    .replace(/<\/figure>$/, "")
    .replace(
      /^<svg viewBox="([^"]+)">/,
      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="$1" width="320" height="320" role="img" aria-label="CrowdVault's wax seal"><style>${STYLE.trim()}</style>`,
    );
  if (!svg.startsWith("<svg xmlns")) throw new Error("unexpected markup from Seal");
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, svg + "\n");
  console.log(`wrote ${out}`);
} finally {
  await server.close();
}
