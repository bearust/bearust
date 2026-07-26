import { expect, test, type Page } from "@playwright/test";

const secret = "provider-secret-must-not-render";
const admin = { id: 1, email: "administrator@example.com", role: "admin", disabled: false };
const viewer = { id: 2, email: "viewer@example.com", role: "viewer", disabled: false };

async function mockAdvisorDashboard(page: Page, options: { locale: "en" | "id" | "ja"; role?: "admin" | "viewer"; enabled?: boolean; }) {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.addInitScript(({ locale }) => window.localStorage.setItem("bearust.locale.v1", locale), { locale: options.locale });
  await page.route("**/api/**", async (route) => {
    const { pathname } = new URL(route.request().url());
    const json = (body: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
    if (pathname === "/api/setup/status") return json({ initialized: true });
    if (pathname === "/api/auth/me") return json(options.role === "viewer" ? viewer : admin);
    if (pathname === "/api/ai-advisor/status") return json({ enabled: options.enabled ?? true });
    if (pathname === "/api/ai-advisor/insights") return json({ page: 1, page_size: 20, total: options.enabled === false ? 0 : 1, items: options.enabled === false ? [] : [{ job_id: "00000000-0000-4000-8000-000000000001", workflow: "configuration_draft", status: "completed", redacted_input: {}, redacted_result: { workflow: "configuration_draft", summary: "Safe redacted proposal", action: "set_waf_mode", mode: "monitor-only", expected_config_hash: "a".repeat(64) }, error_code: null, provider_model: "private-model", config_version: "v1", config_hash: "a".repeat(64), created_at: "2026-01-01", updated_at: "2026-01-01", expires_at: "2099-01-01", draft_decision: null, draft_decided_at: null }] });
    if (pathname.includes("/api/ai-advisor/drafts/") && route.request().method() === "POST") return json({ status: "approved" });
    if (pathname === "/api/proxy-hosts" || pathname === "/api/certificates" || pathname === "/api/users" || pathname === "/api/roles" || pathname === "/api/waf/rules" || pathname === "/api/bot/trusted-crawlers" || pathname === "/api/analytics/timeseries" || pathname === "/api/analytics/anomalies" || pathname === "/api/adaptive-tuning/recommendations") return json([]);
    if (pathname === "/api/audit-logs") return json({ items: [], page: 1, page_size: 25, total: 0 });
    if (pathname === "/api/events") return route.fulfill({ contentType: "text/event-stream", body: "" });
    if (pathname === "/api/waf/config") return json({ mode: "monitor-only", updated_at: "2026-01-01" });
    if (pathname === "/api/bot/config") return json({ mode: "monitor", threshold: 50, ttl_seconds: 300, updated_at: "2026-01-01" });
    if (pathname === "/api/rate-limit/config") return json({ enabled: true, action: "monitor", capacity: 100, refill_per_second: 10, key_scope: "proxy_host_ip", updated_at: "2026-01-01" });
    if (pathname === "/api/analytics/summary") return json({ requests: 0, status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0, waf_blocks: 0, bot_blocks: 0, bot_challenges: 0, rate_limited: 0, p50_ms: null, p95_ms: null, p99_ms: null });
    if (pathname === "/api/analytics/baseline") return json({ host_id: null, status: "warming_up", window: "5m", sample_count: 0, metrics: { req_per_sec: 0, total_requests: 0, status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0, error_rate_percent: 0, p50_ms: null, p95_ms: null, p99_ms: null, waf_blocks: 0, bot_blocks: 0, bot_challenges: 0, rate_limited: 0 }, calculated_at: "2026-01-01" });
    if (pathname.startsWith("/api/adaptive-tuning/policy/")) return json({ mode: "monitor", max_delta_percent: 10, cooldown_seconds: 60, min_confidence: 0.5 });
    return json({});
  });
}

test("disabled advisor is hidden", async ({ page }) => {
  await mockAdvisorDashboard(page, { locale: "en", enabled: false }); await page.goto("/");
  await expect(page.getByTestId("ai-advisor-section")).toHaveCount(0);
});

for (const locale of ["en", "id", "ja"] as const) {
  for (const width of [390, 768, 1280]) {
    test(`${locale} enabled advisor is redacted and responsive at ${width}px`, async ({ page }) => {
      await mockAdvisorDashboard(page, { locale }); await page.setViewportSize({ width, height: 900 }); await page.goto("/");
      const advisor = page.getByTestId("ai-advisor-section"); await expect(advisor).toBeVisible(); await expect(advisor).toContainText("Safe redacted proposal");
      await expect(advisor).not.toContainText(secret); await expect(advisor).not.toContainText("private-model");
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    });
  }
}

test("admin can approve while viewer remains read-only", async ({ page, context }) => {
  await mockAdvisorDashboard(page, { locale: "en", role: "admin" }); await page.goto("/");
  const advisor = page.getByTestId("ai-advisor-section"); await expect(advisor.getByRole("button", { name: "Approve draft" })).toBeVisible();
  await advisor.getByRole("button", { name: "Approve draft" }).click();
  const viewerPage = await context.newPage(); await mockAdvisorDashboard(viewerPage, { locale: "en", role: "viewer" }); await viewerPage.goto("/");
  const viewerAdvisor = viewerPage.getByTestId("ai-advisor-section"); await expect(viewerAdvisor).toBeVisible(); await expect(viewerAdvisor.getByRole("button", { name: "Approve draft" })).toHaveCount(0); await expect(viewerAdvisor.getByRole("button", { name: "Analyze" })).toHaveCount(0); await viewerPage.close();
});
