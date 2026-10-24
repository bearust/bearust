// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { act } from "react";
import { api } from "@/api";
import { renderRoute } from "@/test-utils/render-route";
import { Route as LoginRoute } from "./(auth)/login";

describe("Login route", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = "";
  });

  it("lists enabled identity providers and reports SSO failures", async () => {
    vi.spyOn(api, "ssoProviders").mockResolvedValue([{ slug: "corp", name: "Corp SSO", kind: "oidc" }]);
    window.history.replaceState(null, "", "/login?sso_error=state_expired");
    const { element } = await renderRoute([LoginRoute], "/login");
    await act(async () => {});
    const link = [...element.querySelectorAll("a")].find((a) => a.textContent === "Continue with Corp SSO");
    expect(link?.getAttribute("href")).toBe("/api/auth/sso/corp/start");
    expect(element.textContent).toContain("Single sign-on failed: state_expired");
    window.history.replaceState(null, "", "/");
  });

  it("submits the login form and shows a server error inline", async () => {
    vi.spyOn(api, "ssoProviders").mockResolvedValue([]);
    vi.spyOn(api, "login").mockRejectedValue(
      Object.assign(new Error("Invalid email or password"), { status: 401 }),
    );
    const { element } = await renderRoute([LoginRoute], "/login");
    const form = element.querySelector("form") as HTMLFormElement;
    expect(form).toBeTruthy();
    await act(async () => {
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(element.textContent).toContain("Invalid email or password");
  });
});
