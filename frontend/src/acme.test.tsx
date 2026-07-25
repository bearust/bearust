import {describe,expect,it,vi,afterEach} from 'vitest';
import {api} from './api';
import {acmeSubmissionReady,sanitizeError,validHostname} from './App';

describe('ACME wizard validation',()=>{
  it('accepts normal HTTP-01 names and rejects wildcards',()=>{
    expect(validHostname('Example.com','http01')).toBe(true);
    expect(validHostname('*.example.com','http01')).toBe(false);
  });
  it('allows wildcards only with Cloudflare DNS-01',()=>{
    expect(validHostname('*.example.com','cloudflare_dns01')).toBe(true);
    expect(validHostname('*.*.example.com','cloudflare_dns01')).toBe(false);
  });
  it('replaces unknown error details with safe localized copy',()=>{
    const secret = 'cloudflare_api_token=super-secret-token-value-123456789012345';
    expect(sanitizeError(secret)).toBe('Unable to complete the request. Please try again.');
    expect(sanitizeError(secret)).not.toContain('super-secret');
    expect(sanitizeError('invalid hostname')).toBe('Unable to complete the request. Please try again.');
  });
  it('requires a Cloudflare token for DNS-01 but not HTTP-01',()=>{
    expect(acmeSubmissionReady('cloudflare_dns01',['example.com'],'')).toBe(false);
    expect(acmeSubmissionReady('cloudflare_dns01',['example.com'],'token')).toBe(true);
    expect(acmeSubmissionReady('http01',['example.com'],'')).toBe(true);
  });
});

describe('ACME API contracts',()=>{
  afterEach(()=>vi.restoreAllMocks());
  it('posts HTTP-01 requests and accepts the 202 job shape',async()=>{
    const fetchMock=vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({job_id:'job-1',certificate_id:null,status:'pending'}),{status:202,headers:{'Content-Type':'application/json'}}));
    await expect(api.issueAcme({environment:'staging',challenge:'http01',hostnames:['example.com']})).resolves.toMatchObject({job_id:'job-1',status:'pending'});
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({environment:'staging',challenge:'http01',hostnames:['example.com']});
  });
  it('refreshes status through the per-certificate endpoint',async()=>{
    vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({certificate_id:4,environment:'staging',challenge:'http01',hostnames:['example.com'],renewal_state:'pending',next_renewal_at:null,last_attempt_at:null,last_error_code:null}),{status:200,headers:{'Content-Type':'application/json'}}));
    await api.certificateStatus(4);
    expect(vi.mocked(globalThis.fetch).mock.calls[0][0]).toBe('/api/certificates/4/status');
  });
});
