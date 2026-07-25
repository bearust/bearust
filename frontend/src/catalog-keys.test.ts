import { describe, expect, it } from "vitest";
import componentSource from "./App.tsx?raw";
import uiSource from "./ui.tsx?raw";
import en from "./locales/en.json";

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

  it("keeps dynamic translation families bounded by runtime enums", () => {
    const catalogKeys = new Set(flatten(en));
    const families = {
      "anomaly.rules": ["request_rate", "error_rate", "latency", "security_events"],
      anomaly: ["info", "warning", "critical"],
      "dashboard.realtimeStates": ["connecting", "connected", "disconnected"],
      "roles.builtin": ["admin", "operator", "viewer"],
    };

    for (const [family, values] of Object.entries(families)) {
      for (const value of values) expect(catalogKeys, `${family}.${value}`).toContain(`${family}.${value}`);
    }
  });
});
