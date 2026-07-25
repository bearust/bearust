import { expect, test, type Page } from "@playwright/test";

const admin = {
  id: 1,
  email: "administrator@example.com",
  role: "admin",
  disabled: false,
};
const longEmail = `${"administrator".repeat(18)}@example.com`;

async function mockDashboardApi(page: Page, locale: "id" | "ja") {
  await page.addInitScript((language) => {
    window.localStorage.setItem("bearust.locale.v1", language);
  }, locale);

  await page.route("**/api/**", async (route) => {
    const { pathname } = new URL(route.request().url());
    const json = (body: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });

    if (pathname === "/api/setup/status") return json({ initialized: true });
    if (pathname === "/api/auth/me") return json(admin);
    if (pathname === "/api/proxy-hosts") return json([]);
    if (pathname === "/api/certificates") return json([]);
    if (pathname === "/api/users") return json([admin, { ...admin, id: 2, email: longEmail, role: "operator" }]);
    if (pathname === "/api/roles") return json([]);
    if (pathname === "/api/waf/config") return json({ mode: "monitor-only", updated_at: "2026-07-25T00:00:00Z" });
    if (pathname === "/api/waf/rules" || pathname === "/api/bot/trusted-crawlers" || pathname === "/api/analytics/timeseries" || pathname === "/api/analytics/anomalies" || pathname === "/api/adaptive-tuning/recommendations") return json([]);
    if (pathname === "/api/bot/config") return json({ mode: "monitor", threshold: 50, ttl_seconds: 300, updated_at: "2026-07-25T00:00:00Z" });
    if (pathname === "/api/rate-limit/config") return json({ enabled: true, action: "monitor", capacity: 100, refill_per_second: 10, key_scope: "proxy_host_ip", updated_at: "2026-07-25T00:00:00Z" });
    if (pathname === "/api/analytics/summary") return json({ requests: 0, status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0, waf_blocks: 0, bot_blocks: 0, bot_challenges: 0, rate_limited: 0, p50_ms: null, p95_ms: null, p99_ms: null });
    if (pathname === "/api/analytics/baseline") return json({ host_id: null, status: "warming_up", window: "5m", sample_count: 0, metrics: { req_per_sec: 0, total_requests: 0, status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0, error_rate_percent: 0, p50_ms: null, p95_ms: null, p99_ms: null, waf_blocks: 0, bot_blocks: 0, bot_challenges: 0, rate_limited: 0 }, calculated_at: "2026-07-25T00:00:00Z" });
    if (pathname.startsWith("/api/adaptive-tuning/policy/")) return json({ mode: "monitor", max_delta_percent: 10, cooldown_seconds: 60, min_confidence: 0.5 });
    if (pathname === "/api/audit-logs") return json({ items: [], page: 1, page_size: 25, total: 0 });
    if (pathname === "/api/events") return route.fulfill({ contentType: "text/event-stream", body: "" });
    return json({});
  });
}

test.describe("localized responsive dashboard", () => {
  for (const [locale, expectedCopy] of [["id", "Buat pengguna"], ["ja", "ユーザーを作成"]] as const) {
    for (const width of [390, 768, 1280]) {
      test(`${locale} at ${width}px keeps page overflow out of the document`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        await mockDashboardApi(page, locale);
        await page.goto("/");

        const usersSection = page.getByTestId("users-section");
        await expect(usersSection).toContainText(expectedCopy);

        await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
        const tableScrollIsAllowed = await usersSection.locator(".overflow-x-auto").evaluate((element) => {
          const styles = getComputedStyle(element);
          return styles.overflowX === "auto" || styles.overflowX === "scroll";
        });
        expect(tableScrollIsAllowed).toBe(true);
      });
    }
  }
});
