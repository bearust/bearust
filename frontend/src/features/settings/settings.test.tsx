// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nextProvider } from "react-i18next";
import { Settings } from ".";
import { api } from "@/api";
import { i18n, initI18n, LocalePreferenceProvider } from "@/i18n";
import { ThemeProvider } from "@/theme";
import { useAuthStore } from "@/stores/auth-store";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ to, children, ...props }: { to: string; children: React.ReactNode }) => <a href={to} {...props}>{children}</a>,
}));

let root: Root;
let storage: Storage;
const notificationKey = "bearust.notifications.v1.7";

async function renderSettings() {
  root = createRoot(document.body);
  await act(async () => root.render(
    <I18nextProvider i18n={i18n}><ThemeProvider><LocalePreferenceProvider accountLocale="en"><Settings /></LocalePreferenceProvider></ThemeProvider></I18nextProvider>,
  ));
}

async function selectTab(name: string) {
  const tab = [...document.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((item) => item.textContent === name)!;
  await act(async () => tab.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, button: 0 })));
}

function button(name: string) {
  return [...document.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent === name)!;
}

beforeEach(async () => {
  const values = new Map<string, string>();
  storage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => { values.set(key, value); },
    removeItem: (key) => { values.delete(key); },
    clear: () => values.clear(),
  } as Storage;
  vi.stubGlobal("localStorage", storage);
  vi.spyOn(api, "getAnalyticsRetention").mockResolvedValue({ retention_minutes: 1440, updated_at: "2026-10-01T00:00:00Z" });
  useAuthStore.getState().setUser({ id: 7, email: "admin@example.com", role: "admin", disabled: false, preferred_locale: "en" });
  await initI18n("en");
});

afterEach(async () => {
  if (root) await act(async () => root.unmount());
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  useAuthStore.getState().reset();
  document.body.innerHTML = "";
});

describe("account settings", () => {
  it("saves notification choices and restores them after remount for the same account", async () => {
    await renderSettings();
    await selectTab("Notifications");
    const checkbox = document.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    await act(async () => checkbox.click());
    expect(localStorage.getItem(notificationKey)).toBeNull();
    await act(async () => button("Save local preferences").click());
    expect(JSON.parse(localStorage.getItem(notificationKey)!)).toEqual({ security: false, certificates: true, cluster: true });
    await act(async () => root.unmount());
    await renderSettings();
    await selectTab("Notifications");
    expect(document.querySelector<HTMLInputElement>('input[type="checkbox"]')!.checked).toBe(false);
  });

  it("does not report a successful save when browser storage is unavailable", async () => {
    await renderSettings();
    await selectTab("Notifications");
    vi.spyOn(storage, "setItem").mockImplementation(() => { throw new Error("quota exceeded"); });
    await act(async () => button("Save local preferences").click());
    expect(document.querySelector('[role="alert"]')?.textContent).toContain("Notification preferences could not be saved");
  });

  it("opens the existing session administration screen", async () => {
    await renderSettings();
    await selectTab("Security");
    expect(document.querySelector('a[href="/users"]')?.textContent).toContain("Review session controls");
  });

  it("reports that the language is local-only when the account API fails", async () => {
    vi.spyOn(api, "updateLocalePreference").mockRejectedValue(new Error("offline"));
    await renderSettings();
    const select = document.querySelector<HTMLSelectElement>("#settings-locale")!;
    await act(async () => {
      select.value = "id";
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
    expect(document.querySelector('[role="status"]')?.textContent).toBe(i18n.t("settings.localeLocalOnly"));
    expect(useAuthStore.getState().user?.preferred_locale).toBe("en");
  });
});
