import { describe, expect, it } from "vitest";
import componentSource from "./App.tsx?raw";
import uiSource from "./ui.tsx?raw";
import en from "./locales/en.json";
import {
  ANOMALY_RULES,
  ANOMALY_SEVERITIES,
} from "./api";
import {
  BUILTIN_ROLE_KEYS,
  SERVER_ERROR_KEYS,
  SERVER_MESSAGE_KEYS,
} from "./App";
import { REALTIME_STATUSES } from "./realtime";

function flatten(value: object, prefix = ""): string[] {
  return Object.entries(value).flatMap(([key, child]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return typeof child === "string" ? [path] : flatten(child, path);
  });
}

describe("dashboard catalog keys", () => {
  const source = `${componentSource}\n${uiSource}`;

  it.each([
    '"Bearust Setup"',
    '"Issue Let\'s Encrypt certificate"',
    '"Certificates"',
    '"Users"',
    '"Basic WAF"',
    '"Bot protection"',
    '"Rate limiting"',
    '"Analytics"',
    '"Traffic Baseline"',
    '"Anomaly Detection"',
    '"Adaptive Tuning"',
    '"Proxy Hosts"',
    '"Audit Log"',
    '"Analytics filters"',
    '"Proxy host"',
    '"All hosts"',
    '"Loading analytics…"',
    '"Latency percentiles"',
    '"Security events"',
    '"Analytics by minute"',
    '"Warming up"',
    '"Baseline ready"',
    '"Loading baseline…"',
    '"Req / sec"',
    '"Monitor-only"',
    '"All severities"',
    '"Loading anomalies…"',
    '"Traffic anomalies"',
    '"Acknowledge"',
    '"Acknowledged"',
    '"Adaptive tuning policy saved."',
    '"Emergency Disabled"',
    '"Save Tuning Policy"',
    '"Recommendations & History"',
    '"Challenge unavailable. Please try again."',
    '"Challenge verification failed. Please try again."',
    '"Add Proxy Host"',
    '"Upstream host"',
    '"TLS mode"',
    '"Select certificate"',
    '"No audit log entries found."',
    '"Actor ID filter"',
    '"Theme"',
    '"System"',
    '"Light"',
    '"Dark"',
  ])("does not keep %s as inline user-facing copy", (literal) => {
    expect(source).not.toContain(literal);
  });

  it("keeps visible JSX text and accessible copy in the catalog", () => {
    const inlineText =
      source.match(
        /<(?:h[1-6]|p|span|button|th|td|caption|option)\b[^>]*>\s*[A-Za-z][^<{]*\s*<\//g,
      ) ?? [];
    const inlineCopyAttributes =
      source.match(/(?:aria-label|label|placeholder|title)="[^"\n]+"/g) ?? [];

    expect(inlineText).toEqual([]);
    expect(inlineCopyAttributes).toEqual([]);
  });

  it("references only catalogued literal translation keys", () => {
    const catalogKeys = new Set(flatten(en));
    const literalKeys = [...source.matchAll(/\bt\(\s*["']([^"']+)["']/g)].map((match) => match[1]);

    for (const key of literalKeys) {
      expect(catalogKeys, key).toContain(key);
    }
  });

  it("maps every anomaly runtime enum to a catalog key", () => {
    const catalogKeys = new Set(flatten(en));
    for (const value of ANOMALY_RULES) expect(catalogKeys, `anomaly.rules.${value}`).toContain(`anomaly.rules.${value}`);
    for (const value of ANOMALY_SEVERITIES) expect(catalogKeys, `anomaly.${value}`).toContain(`anomaly.${value}`);
  });

  it("keeps other dynamic translation families bounded by runtime enums", () => {
    const catalogKeys = new Set(flatten(en));
    for (const value of REALTIME_STATUSES) expect(catalogKeys, `dashboard.realtimeStates.${value}`).toContain(`dashboard.realtimeStates.${value}`);
    for (const key of Object.values(BUILTIN_ROLE_KEYS)) expect(catalogKeys, key).toContain(key);
  });

  it("keeps every allowlisted API error mapping catalogued", () => {
    const catalogKeys = new Set(flatten(en));
    for (const key of [...Object.values(SERVER_ERROR_KEYS), ...Object.values(SERVER_MESSAGE_KEYS)]) {
      expect(catalogKeys, key).toContain(key);
    }
  });
});
