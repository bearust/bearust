import { expect, test } from "@playwright/test";

test.describe("BeaRust shadcn-admin shell", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/");
  });

  test("renders the dashboard shell and opens command navigation", async ({ page }) => {
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
    await expect(page.getByText("BeaRust Control Plane")).toBeVisible();
    await expect(page.getByText("Demo data")).toBeVisible();
    await expect(page.getByText("Traffic overview")).toBeVisible();
    await expect(page.getByText("Recent security events")).toBeVisible();

    await page.getByRole("button", { name: /Search anything/i }).click();
    const commandDialog = page.getByRole("dialog");
    await expect(commandDialog).toBeVisible();
    await commandDialog.getByPlaceholder("Jump to a BeaRust section...").fill("proxy");
    await expect(commandDialog.getByText("Proxy Hosts")).toBeVisible();
    await commandDialog.getByText("Proxy Hosts").click();
    await expect(page).toHaveURL(/\/proxy-hosts$/);
    await expect(page.getByRole("heading", { name: "Proxy Hosts" })).toBeVisible();
  });

  test("uses the template-styled login page in demo mode", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByText("Protect every service at the edge.")).toBeVisible();
    await expect(page.getByText("Sign in", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Email")).toBeVisible();
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  });

  test("supports team, theme, account, and proxy-host interactions", async ({ page }) => {
    const teamButton = page.getByRole("button", { name: /BeaRust Control Plane/ });
    await teamButton.click();
    await expect(page.getByRole("menuitem", { name: /Production Cluster/ })).toBeVisible();
    await page.getByRole("menuitem", { name: /Production Cluster/ }).click();
    await expect(page.getByText("Production Cluster", { exact: true }).first()).toBeVisible();

    await page.getByRole("button", { name: "Change theme" }).click();
    await page.getByRole("menuitem", { name: "Dark" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

    await page.getByRole("button", { name: "Open account menu" }).click();
    await page.getByRole("menuitem", { name: "Settings" }).click();
    await expect(page).toHaveURL(/\/settings$/);
    await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();

    await page.goto("/proxy-hosts");
    await page.getByRole("button", { name: "Add proxy host" }).click();
    await expect(page.getByRole("dialog", { name: "Add proxy host" })).toBeVisible();
    await page.getByLabel("Display name").fill("Status page");
    await page.getByLabel("Domain").fill("status.bearust.local");
    await page.getByLabel("Upstream target").fill("status:8080");
    await page.getByRole("button", { name: "Create host" }).click();
    await expect(page.getByText("status.bearust.local", { exact: true })).toBeVisible();
    await expect(page.getByText("Proxy host added")).toBeVisible();
  });

  test("switches dashboard tabs and exports a dummy report", async ({ page }) => {
    await page.getByRole("tab", { name: "Analytics" }).click();
    await expect(page.getByText("Traffic analytics")).toBeVisible();
    await expect(page.getByText("Unique visitors")).toBeVisible();

    await page.getByRole("button", { name: "Export report" }).click();
    await expect(page.getByText("Report prepared")).toBeVisible();
  });
});
