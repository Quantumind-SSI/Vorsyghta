import { describe, it, expect } from 'vitest';
import { buildContentSecurityPolicy } from './security-headers';

describe('Content Security Policy', () => {
  it('dev environment allows unsafe-inline for styles and no nonce', () => {
    const csp = buildContentSecurityPolicy('abc', 'development');
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    expect(csp).not.toContain("style-src 'self' 'nonce-");
  });

  it('production environment allows inline styles (styled-jsx) and adds a style nonce', () => {
    const csp = buildContentSecurityPolicy('xyz', 'production');
    expect(csp).toContain("style-src 'self' 'unsafe-inline' 'nonce-xyz'");
    expect(csp).not.toMatch(/style-src[^;]*'unsafe-eval'/);
  });
});
