import { describe, expect, it } from 'vitest';
import componentSource from './App.tsx?raw';

describe('dashboard catalog keys', () => {
  it.each([
    '"Bearust Setup"', '"Issue Let\'s Encrypt certificate"', '"Certificates"', '"Users"',
    '"Basic WAF"', '"Bot protection"', '"Rate limiting"', '"Analytics"', '"Traffic Baseline"',
    '"Anomaly Detection"', '"Adaptive Tuning"', '"Proxy Hosts"', '"Audit Log"',
  ])('does not keep %s as inline dashboard copy', (literal) => {
    expect(componentSource).not.toContain(literal);
  });
});
