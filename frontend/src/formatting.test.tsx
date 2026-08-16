// @vitest-environment jsdom
import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AnalyticsSection, AuditLogSection, BaselineSection } from './App';
import { api, type User } from './api';
import { formatLocaleDate, formatLocaleNumber, i18n, type Locale } from './i18n';

vi.mock('./api', async () => {
  const actual = await vi.importActual<typeof import('./api')>('./api');
  return {
    ...actual,
    api: {
      ...actual.api,
      auditLogs: vi.fn(),
      getAnalyticsSummary: vi.fn(),
      getAnalyticsTimeseries: vi.fn(),
      getBaseline: vi.fn(),
    },
  };
});

const user: User = { id: 1, email: 'admin@example.com', role: 'admin', disabled: false };
const hosts = [{ id: 1, name: 'Primary host', domain: 'example.com', upstream_host: '127.0.0.1', upstream_port: 80, tls_mode: 'disabled', certificate_id: null, enabled: true }];
const timestamp = '2026-07-22T10:00:00Z';

afterEach(async () => {
  await i18n.changeLanguage('en');
  vi.restoreAllMocks();
  document.body.innerHTML = '';
});

describe('localized dashboard formatting', () => {
  it.each(['en', 'id', 'ja'] as const)('formats audit, analytics, and baseline values in %s', async (locale: Locale) => {
    vi.mocked(api.auditLogs).mockResolvedValue({
      items: [{ id: 1, actor: 'admin@example.com', event: 'login', details: 'safe detail', created_at: timestamp }],
      page: 1,
      page_size: 25,
      total: 12_345,
    });
    vi.mocked(api.getAnalyticsSummary).mockResolvedValue({
      requests: 1_234_567,
      status_2xx: 1_200_000,
      status_3xx: 0,
      status_4xx: 12,
      status_5xx: 4,
      waf_blocks: 7_654,
      bot_blocks: 0,
      bot_challenges: 0,
      rate_limited: 8_765,
      bandwidth_bytes: 98_765,
      p50_ms: 12.5,
      p95_ms: 40.25,
      p99_ms: 50.75,
    });
    vi.mocked(api.getAnalyticsTimeseries).mockResolvedValue([]);
    vi.mocked(api.getBaseline).mockResolvedValue({
      host_id: 1,
      status: 'ready',
      window: '5m',
      sample_count: 2,
      metrics: {
        req_per_sec: 1_234.5,
        total_requests: 30,
        status_2xx: 20,
        status_3xx: 0,
        status_4xx: 5,
        status_5xx: 5,
        error_rate_percent: 12.3,
        p50_ms: 10,
        p95_ms: 20,
        p99_ms: 30,
        waf_blocks: 0,
        bot_blocks: 0,
        bot_challenges: 0,
        rate_limited: 0,
      },
      calculated_at: timestamp,
    });

    await act(async () => { await i18n.changeLanguage(locale); });
    const host = document.createElement('div');
    document.body.append(host);
    const root = createRoot(host);
    await act(async () => {
      root.render(<><AuditLogSection user={user} /><AnalyticsSection hosts={hosts} /><BaselineSection hosts={hosts} /></>);
    });
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 200)); });

    expect(host.textContent).toContain(formatLocaleDate(timestamp, locale, { dateStyle: 'medium', timeStyle: 'short' }));
    expect(host.textContent).toContain(formatLocaleNumber(1_234_567, locale, { maximumFractionDigits: 0 }));
    expect(host.textContent).toContain(formatLocaleNumber(7_654, locale, { maximumFractionDigits: 0 }));
    expect(host.textContent).toContain(formatLocaleNumber(8_765, locale, { maximumFractionDigits: 0 }));
    expect(host.textContent).toContain(formatLocaleNumber(12.3 / 100, locale, { style: 'percent', minimumFractionDigits: 1, maximumFractionDigits: 1 }));
    expect(host.textContent).toContain(formatLocaleNumber(1_234.5, locale, { minimumFractionDigits: 2, maximumFractionDigits: 2 }));
    root.unmount();
  });
});
