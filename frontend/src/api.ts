import type { Locale } from './i18n';

export type Role=string;
export type User={id:number;email:string;role:Role;disabled:boolean;preferred_locale?:Locale|null};
export type PermissionKey='proxy_hosts.read'|'proxy_hosts.write'|'certificates.read'|'certificates.write'|'users.manage'|'roles.manage'|'audit_logs.read'|'audit_logs.export'|'system.settings.manage'|'sessions.revoke'|'bot_protection.manage'|'ai_advisor.read'|'ai_advisor.request'|'ai_advisor.approve'|'plugins.read'|'plugins.manage';
export type RolePermissionScope={permission:'proxy_hosts.read'|'proxy_hosts.write';proxy_host_ids:number[]};
export type RoleRecord={id:number;slug:string;name:string;description:string;system_managed:boolean;permissions:PermissionKey[];scopes?:RolePermissionScope[]};
export type Host={id:number;name:string;domain:string;upstream_host:string;upstream_port:number;tls_mode:string;certificate_id:number|null;enabled:boolean};
export type LoadBalancerAlgorithm='round_robin'|'least_connections'|'weighted'|'ip_hash'|'adaptive_weight'|'plugin';
export type LoadBalancerHealthCheck='tcp'|'http';
export type LoadBalancerBackend={id:number;address:string;health_check:LoadBalancerHealthCheck;health_path:string|null;weight:number;healthy:boolean;inflight:number;response_time_ewma_ms:number|null;passive_failures:number};
export type LoadBalancerPool={name:string;algorithm:LoadBalancerAlgorithm;connect_timeout_seconds:number;request_timeout_seconds:number;passive_health:boolean;backends:LoadBalancerBackend[]};
export type LoadBalancerRoute={name:string;host:string;path_prefix:string;upstream_pool:string};
export type LoadBalancerSnapshot={generation:number;pools:LoadBalancerPool[];routes:LoadBalancerRoute[];capabilities:{algorithms:string[];health_checks:string[];passive_health:boolean;adaptive_weighting:boolean}};
export type LoadBalancerConfigRequest={pools:Array<{name:string;algorithm:LoadBalancerAlgorithm;connect_timeout_seconds:number;request_timeout_seconds:number;passive_health:boolean;backends:Array<{address:string;health_check:LoadBalancerHealthCheck;health_path:string|null;weight:number}>}>;routes:LoadBalancerRoute[]};
export type Certificate={id:number;name:string;source:string;covered_hostnames:string[];expiry:string;active:boolean;acme?:AcmeStatus|null};
export type CertificateUploadResponse={id:number;name:string;source:string;covered_hostnames:string[];expiry:string};
export type AcmeRequest={environment:'staging'|'production';challenge:'http01'|'cloudflare_dns01';hostnames:string[];cloudflare_api_token?:string};
export type AcmeJob={job_id:string;certificate_id:number|null;status:string};
export type AcmeStatus={certificate_id:number;environment:'staging'|'production';challenge:'http01'|'cloudflare_dns01';hostnames:string[];renewal_state:string;next_renewal_at:string|null;last_attempt_at:string|null;last_error_code:string|null};
export type AuditLogItem={id:number;actor:string;event:string;details:string;created_at:string};
export type AuditLogPage={items:AuditLogItem[];page:number;page_size:number;total:number};
export type AuditLogQuery={event?:string;actor_id?:number;from?:string;to?:string;q?:string;page?:number;page_size?:number};
export type WafMode='monitor-only'|'block';
export type WafAction='inherit'|'allow'|'log'|'block';
export type WafConfig={mode:WafMode;updated_at:string};
export type WafRule={id:number;name:string;source:string;category:string;severity:string;enabled:boolean;action:WafAction;matcher_json:string;created_at:string;updated_at:string};
export type IpSecurityAction='monitor'|'block'|'allow';
export type IpSecurityRule={id:number;cidr:string;action:IpSecurityAction;score:number;country_code:string|null;enabled:boolean;created_at:string;updated_at:string};
export type ProxyHostAuth={host_id:number;enabled:boolean;realm:string;username:string;updated_at:string};
export type WafFeedback={id:number;reporter_id:number|null;request_id:string|null;rule_id:number|null;label:'false_positive'|'true_positive';note:string;created_at:string};
export type BotMode='monitor'|'challenge'|'block';
export type BotConfig={mode:BotMode;threshold:number;ttl_seconds:number;updated_at:string};
export type TrustedCrawler={id:number;category:'trusted_crawler';weight:number;trusted_user_agent:string|null;trusted_domain:string|null;enabled:boolean};
export type BotChallenge={token:string;difficulty:number;expires_at:number;fingerprint_prefix:string};
export type RateLimitAction='monitor'|'block';
export type RateLimitKeyScope='proxy_host_ip'|'proxy_host_path_ip';
export type RateLimitConfig={enabled:boolean;action:RateLimitAction;capacity:number;refill_per_second:number;key_scope:RateLimitKeyScope;updated_at:string};
export type AnalyticsSummary={requests:number;status_2xx:number;status_3xx:number;status_4xx:number;status_5xx:number;waf_blocks:number;bot_blocks:number;bot_challenges:number;rate_limited:number;bandwidth_bytes:number;p50_ms:number|null;p95_ms:number|null;p99_ms:number|null};
export type AnalyticsBucket={timestamp:string;proxy_host_id:number;requests:number;status_2xx:number;status_3xx:number;status_4xx:number;status_5xx:number;waf_blocks:number;bot_blocks:number;bot_challenges:number;rate_limited:number;bandwidth_bytes:number;p50_ms:number|null;p95_ms:number|null;p99_ms:number|null};
export type AnalyticsCount={key:string;count:number};
export type AnalyticsDimensions={bandwidth_bytes:number;top_endpoints:AnalyticsCount[];top_upstreams:AnalyticsCount[];top_attacker_ips:AnalyticsCount[];attack_types:AnalyticsCount[]};
export type AnalyticsRetentionConfig={retention_minutes:number;updated_at:string};
export type AnalyticsQuery={proxy_host_id?:number;from?:string;to?:string;limit?:number};

export type BaselineWindow = '5m' | '1h' | '24h';
export type BaselineStatus = 'warming_up' | 'ready';
export type BaselineMetrics = { req_per_sec: number; total_requests: number; status_2xx: number; status_3xx: number; status_4xx: number; status_5xx: number; error_rate_percent: number; p50_ms: number | null; p95_ms: number | null; p99_ms: number | null; waf_blocks: number; bot_blocks: number; bot_challenges: number; rate_limited: number; };
export type BaselineSnapshot = { host_id: number | null; status: BaselineStatus; window: BaselineWindow; sample_count: number; metrics: BaselineMetrics; calculated_at: string; };

export const ANOMALY_RULES = ['request_rate', 'error_rate', 'latency', 'security_events'] as const;
export const ANOMALY_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type AnomalyRule = (typeof ANOMALY_RULES)[number];
export type AnomalySeverity = (typeof ANOMALY_SEVERITIES)[number];
export type AnomalyRecord = { id: number; host_id: number; rule: AnomalyRule; severity: AnomalySeverity; score: number; summary: string; observed_at: string; acknowledged: boolean };

export type TuningMode = 'monitor' | 'recommend' | 'enforce';
export type TuningPolicy = { mode: TuningMode; max_delta_percent: number; cooldown_seconds: number; min_confidence: number };
export type PolicyRecommendation = { id: number; host_id: number; patch: { capacity?: number; refill_per_second?: number; waf_mode?: WafMode }; confidence: number; reason: string; created_at: string; applied: boolean };
export type AdvisorWorkflow = 'incident_explanation'|'security_summary'|'rule_tuning'|'configuration_draft';
export type AdvisorStatus = { enabled: boolean };
export type AdvisorJobStatus = 'queued'|'running'|'completed'|'failed'|'approved'|'rejected'|'expired';
export type AdvisorErrorCode = 'advisor_disabled'|'advisor_busy'|'advisor_timeout'|'advisor_provider_unavailable'|'advisor_invalid_response'|'advisor_response_too_large'|'advisor_circuit_open'|'advisor_invalid_request'|'advisor_stale_draft'|'advisor_expired';
export type AdvisorInsightWorkflow = 'incident_explanation'|'security_summary'|'rule_tuning';
export type InsightSeverity = 'info'|'warning'|'critical';
export type AdvisorInsightResult = { workflow: AdvisorInsightWorkflow; summary: string; severity: InsightSeverity; signals: string[]; reason_ids: string[]; score: number };
export type AdvisorDraftResult = { workflow: 'configuration_draft'; summary: string; action: 'set_waf_mode'; mode: WafMode; expected_config_hash: string };
export type AdvisorResult = AdvisorInsightResult | AdvisorDraftResult;
export type AdvisorJob = { job_id: string; workflow: AdvisorWorkflow; status: AdvisorJobStatus; redacted_input: Record<string, unknown>; redacted_result: AdvisorResult | null; error_code: AdvisorErrorCode | null; provider_model: string; config_version: string; config_hash: string; created_at: string; updated_at: string; expires_at: string; draft_decision: 'approved'|'rejected'|null; draft_decided_at: string | null };
export type AdvisorInsight = AdvisorJob;
export type AdvisorDraft = AdvisorJob & { workflow: 'configuration_draft'; redacted_result: AdvisorDraftResult | null };
export type AdvisorJobPage = { items: AdvisorInsight[]; page: number; page_size: number; total: number };
export type AdvisorAnalysisRequest = { workflow: AdvisorWorkflow; host_id?: number; from?: string; to?: string; command?: string };
export type ClusterPeer = { node_id: string; status: 'healthy'|'unhealthy'|'unreachable'|'timeout'; latency_ms: number|null; error: string|null };
export type ClusterSnapshot = { local_node_id: string; cluster_enabled: boolean; total_peers: number; healthy_peers: number; peers: ClusterPeer[]; timestamp: string; raft_role: 'standalone'|'leader'|'follower'|'candidate'|'unknown'; raft_leader_id: string|null; raft_term: number; raft_last_log_index: number; raft_commit_index: number; raft_quorum_available: boolean; raft_sync_state: string };
export type PluginStatus = { id: string; display_name: string; abi_version: number; digest: string; enabled: boolean; loaded: boolean; last_error_code: string|null; created_at: string; updated_at: string; trust_status: string };
export type PluginReloadResponse = { loaded: number; failed: number };
export type PluginHealthResponse = { status: number; elapsed_ms: number; detail: string|null };

export type ApiError = Error & { status: number; code?: string };

function apiError(response: Response, payload: unknown): ApiError {
  const body = payload && typeof payload === 'object' ? payload as { code?: unknown; message?: unknown } : {};
  const error = new Error(typeof body.message === 'string' ? body.message : '') as ApiError;
  error.status = response.status;
  if (typeof body.code === 'string') error.code = body.code;
  return error;
}

async function request<T>(path:string,init:RequestInit={}):Promise<T>{const r=await fetch(path,{...init,credentials:'include',headers:{'Content-Type':'application/json',...(init.headers||{})}});if(!r.ok)throw apiError(r,await r.json().catch(()=>null));return r.status===204?undefined as T:r.json()}
async function requestText(path:string):Promise<string>{const r=await fetch(path,{credentials:'include'});if(!r.ok)throw apiError(r,await r.json().catch(()=>null));return r.text()}
async function requestForm<T>(path:string,init:RequestInit={}):Promise<T>{const r=await fetch(path,{...init,credentials:'include'});if(!r.ok)throw apiError(r,await r.json().catch(()=>null));return r.status===204?undefined as T:r.json()}
export const api={
 status:()=>request<{initialized:boolean}>('/api/setup/status'),setup:(x:object)=>request<User>('/api/setup/initialize',{method:'POST',body:JSON.stringify(x)}),login:(x:object)=>request<User>('/api/auth/login',{method:'POST',body:JSON.stringify(x)}),me:()=>request<User>('/api/auth/me'),updateLocalePreference:(preferred_locale:Locale|null)=>request<User>('/api/auth/me/preferences',{method:'PATCH',body:JSON.stringify({preferred_locale})}),logout:()=>request<void>('/api/auth/logout',{method:'POST'}),
 hosts:()=>request<Host[]>('/api/proxy-hosts'),createHost:(x:object)=>request<Host>('/api/proxy-hosts',{method:'POST',body:JSON.stringify(x)}),updateHost:(id:number,x:object)=>request<Host>(`/api/proxy-hosts/${id}`,{method:'PATCH',body:JSON.stringify(x)}),deleteHost:(id:number)=>request<void>(`/api/proxy-hosts/${id}`,{method:'DELETE'}),hostAuth:(id:number)=>request<ProxyHostAuth>(`/api/proxy-hosts/${id}/auth`),updateHostAuth:(id:number,x:{enabled:boolean;realm:string;username:string;password?:string})=>request<ProxyHostAuth>(`/api/proxy-hosts/${id}/auth`,{method:'PUT',body:JSON.stringify(x)}),loadBalancer:()=>request<LoadBalancerSnapshot>('/api/load-balancer'),updateLoadBalancer:(x:LoadBalancerConfigRequest)=>request<LoadBalancerSnapshot>('/api/load-balancer',{method:'PUT',body:JSON.stringify(x)}),
 certificates:()=>request<Certificate[]>('/api/certificates'),uploadCertificate:(x:{name:string;certificate:File;key:File})=>{const body=new FormData();body.append('name',x.name);body.append('certificate',x.certificate);body.append('key',x.key);return requestForm<CertificateUploadResponse>('/api/certificates',{method:'POST',body})},issueAcme:(x:AcmeRequest)=>request<AcmeJob>('/api/certificates/acme',{method:'POST',body:JSON.stringify(x)}),renewCertificate:(id:number)=>request<AcmeJob>(`/api/certificates/${id}/renew`,{method:'POST'}),certificateStatus:(id:number)=>request<AcmeStatus>(`/api/certificates/${id}/status`),activateCertificate:(id:number)=>request<void>(`/api/certificates/${id}/activate`,{method:'POST'}),
 users:()=>request<User[]>('/api/users'),createUser:(x:{email:string;password:string;role:Role})=>request<User>('/api/users',{method:'POST',body:JSON.stringify(x)}),updateUser:(id:number,x:{role?:Role;disabled?:boolean})=>request<User>(`/api/users/${id}`,{method:'PATCH',body:JSON.stringify(x)}),deleteUser:(id:number)=>request<void>(`/api/users/${id}`,{method:'DELETE'}),revokeUserSessions:(id:number)=>request<{revoked:number}>(`/api/users/${id}/sessions/revoke`,{method:'POST'}),
 roles:()=>request<RoleRecord[]>('/api/roles'),createRole:(x:{slug:string;name:string;description:string;permissions:PermissionKey[];scopes?:RolePermissionScope[]})=>request<RoleRecord>('/api/roles',{method:'POST',body:JSON.stringify(x)}),updateRole:(id:number,x:Partial<{name:string;description:string;permissions:PermissionKey[];scopes:RolePermissionScope[]}>)=>request<RoleRecord>(`/api/roles/${id}`,{method:'PATCH',body:JSON.stringify(x)}),deleteRole:(id:number)=>request<void>(`/api/roles/${id}`,{method:'DELETE'}),
 auditLogs:(query:AuditLogQuery={})=>{const params=new URLSearchParams();for(const [key,value] of Object.entries(query)){if(value!==undefined&&value!=='')params.set(key,String(value))}const suffix=params.toString()?`?${params.toString()}`:'';return request<AuditLogPage>(`/api/audit-logs${suffix}`)}
 ,wafConfig:()=>request<WafConfig>('/api/waf/config'),wafRules:()=>request<WafRule[]>('/api/waf/rules'),wafFeedback:()=>request<WafFeedback[]>('/api/waf/feedback'),createWafFeedback:(x:{request_id?:string;rule_id?:number;label:'false_positive'|'true_positive';note?:string})=>request<WafFeedback>('/api/waf/feedback',{method:'POST',body:JSON.stringify(x)}),updateWafConfig:(x:{mode:WafMode})=>request<WafConfig>('/api/waf/config',{method:'PATCH',body:JSON.stringify(x)}),createWafRule:(x:object)=>request<WafRule>('/api/waf/rules',{method:'POST',body:JSON.stringify(x)}),updateWafRule:(id:number,x:object)=>request<WafRule>(`/api/waf/rules/${id}`,{method:'PATCH',body:JSON.stringify(x)}),deleteWafRule:(id:number)=>request<void>(`/api/waf/rules/${id}`,{method:'DELETE'}),importWafRules:(toml:string)=>request<void>('/api/waf/rules/import',{method:'POST',headers:{'Content-Type':'application/toml'},body:toml}),exportWafRules:()=>requestText('/api/waf/rules/export'),
 ipSecurityRules:()=>request<IpSecurityRule[]>('/api/ip-security/rules'),createIpSecurityRule:(x:{cidr:string;action:IpSecurityAction;score:number;country_code?:string|null;enabled?:boolean})=>request<IpSecurityRule>('/api/ip-security/rules',{method:'POST',body:JSON.stringify(x)}),updateIpSecurityRule:(id:number,x:object)=>request<IpSecurityRule>(`/api/ip-security/rules/${id}`,{method:'PATCH',body:JSON.stringify(x)}),deleteIpSecurityRule:(id:number)=>request<void>(`/api/ip-security/rules/${id}`,{method:'DELETE'}),
 botConfig:()=>request<BotConfig>('/api/bot/config'),updateBotConfig:(x:Partial<{mode:BotMode;threshold:number;ttl_seconds:number}>)=>request<BotConfig>('/api/bot/config',{method:'PATCH',body:JSON.stringify(x)}),trustedCrawlers:()=>request<TrustedCrawler[]>('/api/bot/trusted-crawlers'),createTrustedCrawler:(x:{user_agent:string;domain:string;enabled?:boolean})=>request<TrustedCrawler>('/api/bot/trusted-crawlers',{method:'POST',body:JSON.stringify(x)}),updateTrustedCrawler:(id:number,x:{user_agent:string;domain:string;enabled?:boolean})=>request<TrustedCrawler>(`/api/bot/trusted-crawlers/${id}`,{method:'PATCH',body:JSON.stringify(x)}),deleteTrustedCrawler:(id:number)=>request<void>(`/api/bot/trusted-crawlers/${id}`,{method:'DELETE'}),botChallenge:(fingerprint:string)=>request<BotChallenge>('/api/bot/challenge',{method:'POST',body:JSON.stringify({fingerprint})}),verifyBotChallenge:(x:{token:string;fingerprint:string;solution:string})=>request<{ok:boolean}>('/api/bot/challenge/verify',{method:'POST',body:JSON.stringify(x)}),importBotConfig:(toml:string)=>request<void>('/api/bot/config/import',{method:'POST',headers:{'Content-Type':'application/toml'},body:toml}),exportBotConfig:()=>requestText('/api/bot/config/export')
 ,rateLimitConfig:()=>request<RateLimitConfig>('/api/rate-limit/config'),updateRateLimitConfig:(x:Pick<RateLimitConfig,'enabled'|'action'|'capacity'|'refill_per_second'|'key_scope'>)=>request<RateLimitConfig>('/api/rate-limit/config',{method:'PATCH',body:JSON.stringify(x)}),
 getAnalyticsSummary:(query:AnalyticsQuery={})=>{const p=new URLSearchParams();for(const [k,v] of Object.entries(query)){if(v!==undefined&&v!=='')p.set(k,String(v))}const s=p.toString();return request<AnalyticsSummary>(`/api/analytics/summary${s?`?${s}`:''}`)},
 getAnalyticsTimeseries:(query:AnalyticsQuery={})=>{const p=new URLSearchParams();for(const [k,v] of Object.entries(query)){if(v!==undefined&&v!=='')p.set(k,String(v))}const s=p.toString();return request<AnalyticsBucket[]>(`/api/analytics/timeseries${s?`?${s}`:''}`)},
 getAnalyticsDimensions:(query:AnalyticsQuery={})=>{const p=new URLSearchParams();for(const [k,v] of Object.entries(query)){if(v!==undefined&&v!=='')p.set(k,String(v))}const s=p.toString();return request<AnalyticsDimensions>(`/api/analytics/dimensions${s?`?${s}`:''}`)},
 getAnalyticsRetention:()=>request<AnalyticsRetentionConfig>('/api/analytics/retention'),updateAnalyticsRetention:(retention_minutes:number)=>request<AnalyticsRetentionConfig>('/api/analytics/retention',{method:'PATCH',body:JSON.stringify({retention_minutes})}),
 getBaseline:(query:{proxy_host_id?:number;window?:string}={})=>{const p=new URLSearchParams();for(const [k,v] of Object.entries(query)){if(v!==undefined&&v!=='')p.set(k,String(v))}const s=p.toString();return request<BaselineSnapshot>(`/api/analytics/baseline${s?`?${s}`:''}`)},
 getAnomalies:(query:{host_id?:number;severity?:string;rule?:string}={})=>{const p=new URLSearchParams();for(const [k,v] of Object.entries(query)){if(v!==undefined&&v!=='')p.set(k,String(v))}const s=p.toString();return request<AnomalyRecord[]>(`/api/analytics/anomalies${s?`?${s}`:''}`)},
 ackAnomaly:(id:number)=>request<AnomalyRecord>(`/api/analytics/anomalies/${id}/ack`,{method:'POST'}),
 getTuningPolicy:(host_id:number)=>request<TuningPolicy>(`/api/adaptive-tuning/policy/${host_id}`),
 updateTuningPolicy:(host_id:number,x:Partial<TuningPolicy>)=>request<TuningPolicy>(`/api/adaptive-tuning/policy/${host_id}`,{method:'PUT',body:JSON.stringify(x)}),
 getRecommendations:()=>request<PolicyRecommendation[]>('/api/adaptive-tuning/recommendations'),
 applyRecommendation:(id:number)=>request<void>(`/api/adaptive-tuning/recommendations/${id}/apply`,{method:'POST'}),
 rollbackRecommendation:(id:number)=>request<void>(`/api/adaptive-tuning/recommendations/${id}/rollback`,{method:'POST'}),
 emergencyDisableTuning:()=>request<{emergency_disabled:boolean}>('/api/adaptive-tuning/emergency-disable',{method:'POST'}),
 aiAdvisorStatus:()=>request<AdvisorStatus>('/api/ai-advisor/status'),startAiAnalysis:(x:AdvisorAnalysisRequest)=>request<AdvisorJob>('/api/ai-advisor/analyses',{method:'POST',body:JSON.stringify(x)}),listAiInsights:(query:{page?:number;page_size?:number}={})=>{const p=new URLSearchParams();for(const [k,v] of Object.entries(query)){if(v!==undefined)p.set(k,String(v))}const s=p.toString();return request<AdvisorJobPage>(`/api/ai-advisor/insights${s?`?${s}`:''}`)},approveAiDraft:(id:string)=>request<AdvisorDraft>(`/api/ai-advisor/drafts/${id}/approve`,{method:'POST'}),rejectAiDraft:(id:string)=>request<AdvisorDraft>(`/api/ai-advisor/drafts/${id}/reject`,{method:'POST'}),
 clusterStatus:()=>request<ClusterSnapshot>('/api/cluster/status'),plugins:()=>request<PluginStatus[]>('/api/plugins'),reloadPlugins:()=>request<PluginReloadResponse>('/api/plugins/reload',{method:'POST'}),enablePlugin:(id:string)=>request<PluginStatus>(`/api/plugins/${encodeURIComponent(id)}/enable`,{method:'POST'}),disablePlugin:(id:string)=>request<PluginStatus>(`/api/plugins/${encodeURIComponent(id)}/disable`,{method:'POST'}),unloadPlugin:(id:string)=>request<void>(`/api/plugins/${encodeURIComponent(id)}`,{method:'DELETE'}),pluginHealthCheck:(id:string)=>request<PluginHealthResponse>(`/api/plugins/${encodeURIComponent(id)}/health-check`,{method:'POST'})
};
