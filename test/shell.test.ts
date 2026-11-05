/**
 * The Lab's header and footer: with SHELL_URL set, pages go out inside the shell page, with their
 * own title and stylesheet, and a CSP that lets the shell's scripts run.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const LAB_JS = 'document.documentElement.dataset.session = "none";';
const SHELL = `<!doctype html><html><head><title>Proving ground — Agent Lab</title><link rel="canonical" href="https://lab.example/shell/">
<link rel="stylesheet" href="/_astro/Base.css"></head><body><header class="site-header">LAB HEADER</header>
<main><div class="wrap"><!--content--></div></main><footer class="site-footer">LAB FOOTER</footer>
<script type="module">${LAB_JS}</script><script type="module" src="/_astro/Base.js"></script></body></html>`;
const lab = createServer((_, res) => res.end(SHELL)).listen(0);
await once(lab, 'listening');

const port = 20000 + Math.floor(Math.random() * 20000);
const BASE = `http://pg.localhost:${port}/proving-ground`;
Object.assign(process.env, {
  PORT: String(port), BASE_URL: BASE, DATA_DIR: mkdtempSync(join(tmpdir(), 'pg-shell-')),
  SHELL_URL: `http://127.0.0.1:${(lab.address() as { port: number }).port}/shell/`,
});
const { server } = await import('../src/server.ts');
after(() => { server.close(); lab.close(); });

const sha = (js: string) => `'sha256-${createHash('sha256').update(js).digest('base64')}'`;
async function get(path: string) {
  for (let i = 0; ; i++) {
    const r = await fetch(BASE + path);
    const html = await r.text();
    if (html.includes('LAB HEADER') || i === 50) return { html, csp: r.headers.get('content-security-policy') ?? '' };
    await new Promise((ok) => setTimeout(ok, 20));
  }
}

test('the homepage goes out inside the Lab shell', async () => {
  const { html, csp } = await get('/');
  assert.match(html, /LAB HEADER[\s\S]*<div class="pg">[\s\S]*The x401 door[\s\S]*LAB FOOTER/);
  assert.equal(html.match(/<main/g)?.length, 1, 'one main: the page fills the shell\'s');
  assert.match(html, /<title>Proving ground — Agent Lab<\/title>/);
  assert.ok(html.includes(`<link rel="stylesheet" href="/proving-ground/style.css"></head>`));
  assert.doesNotMatch(html, /canonical|fonts\.googleapis/);
  assert.match(csp, /script-src 'self'/);
  assert.ok(csp.includes(sha(LAB_JS)), 'the shell\'s inline script may run');
});

test('a door wall keeps its own script, and the CSP allows it', async () => {
  const { html, csp } = await get('/x401');
  const wall = /<script>([\s\S]*?)<\/script>/.exec(html)![1];
  assert.match(html, /LAB HEADER[\s\S]*id="attempt"[\s\S]*LAB FOOTER/);
  assert.ok(csp.includes(sha(wall)));
});

test('JSON and text are untouched', async () => {
  const r = await fetch(`${BASE}/llms.txt`);
  assert.doesNotMatch(await r.text(), /LAB HEADER/);
});
