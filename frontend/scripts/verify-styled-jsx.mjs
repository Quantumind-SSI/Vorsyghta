#!/usr/bin/env node
import { readdir, readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';

const SRC_ROOT = new URL('../src', import.meta.url).pathname;

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(full);
    } else if (/\.(tsx|ts)$/.test(entry.name)) {
      const content = await readFile(full, 'utf8');
      if (content.includes('<style jsx') || content.includes('<style jsx ') ) {
        const lines = content.split('\n').slice(0, 10);
        const hasUseClient = lines.some(l => l.trim() === "'use client';" || l.trim() === '"use client";');
        if (!hasUseClient) {
          console.error(`[verify-styled-jsx] Styled-jsx used in Server Component: ${full}`);
          console.error('Add \'use client\'; at the top of the file or move styles to CSS modules.');
          process.exit(1);
        }
      }
    }
  }
}

await walk(SRC_ROOT);
console.log('[verify-styled-jsx] OK – all styled-jsx files are client components');
