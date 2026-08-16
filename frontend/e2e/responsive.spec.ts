import { expect, test } from "@playwright/test";

for (const width of [390, 768, 1280]) {
  test(`dashboard shell is usable without page overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
    await expect.poll(() =>
      page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
    ).toBe(true);

    if (width < 768) {
      await page.locator('[data-sidebar="trigger"]').first().click();
      await expect(page.locator('[data-sidebar="sidebar"]').getByText("Proxy Hosts")).toBeVisible();
    } else {
      await expect(page.getByText("General")).toBeVisible();
      await expect(page.getByText("Proxy Hosts").first()).toBeVisible();
    }
  });
}

test("security controls preserve responsive layout and persist demo policy interactions", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await page.goto("/security?tab=waf");
  await expect(page.getByRole("heading", { name: "Security" })).toBeVisible();
  const pauseButton = page.getByRole("button", { name: "Switch to monitor" });
  await pauseButton.click();
  await expect(page.getByRole("button", { name: "Enable blocking" })).toBeVisible();
  await expect.poll(() =>
    page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
  ).toBe(true);
});
