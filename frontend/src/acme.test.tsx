import {describe,expect,it} from 'vitest';
import {sanitizeError,validHostname} from './App';

describe('ACME wizard validation',()=>{
  it('accepts normal HTTP-01 names and rejects wildcards',()=>{
    expect(validHostname('Example.com','http01')).toBe(true);
    expect(validHostname('*.example.com','http01')).toBe(false);
  });
  it('allows wildcards only with Cloudflare DNS-01',()=>{
    expect(validHostname('*.example.com','cloudflare_dns01')).toBe(true);
    expect(validHostname('*.*.example.com','cloudflare_dns01')).toBe(false);
  });
  it('redacts tokens from errors before rendering',()=>{
    expect(sanitizeError('cloudflare_api_token=super-secret-token-value-123456789012345')).toContain('[redacted]');
    expect(sanitizeError('invalid hostname')).toBe('invalid hostname');
  });
});
