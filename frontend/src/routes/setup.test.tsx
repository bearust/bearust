// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { act } from "react";
import { api } from "@/api";
import { renderRoute } from "@/test-utils/render-route";
import { Route as SetupRoute } from "./(auth)/setup";

describe("Setup route", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = "";
  });

  it("submits the setup form and shows a server error inline", async () => {
    vi.spyOn(api, "status").mockResolvedValue({ initialized: false });
    vi.spyOn(api, "setup").mockRejectedValue(
      Object.assign(new Error("Invalid setup token"), { status: 400 }),
    );
    const { element } = await renderRoute([SetupRoute], "/setup");
    const form = element.querySelector("form") as HTMLFormElement;
    expect(form).toBeTruthy();
    await act(async () => {
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    // The real `sanitizeError` (from `@/App`) translates known server
    // messages/codes into a user-facing string rather than surfacing the
    // raw `Error.message` — "Invalid setup token" maps to
    // errors.authInvalidSetupToken.
    expect(element.textContent).toContain("The setup token is invalid.");
  });

  it("redirects to /login when setup is already completed", async () => {
    vi.spyOn(api, "status").mockResolvedValue({ initialized: true });
    const { router } = await renderRoute([SetupRoute], "/setup");
    expect(router.state.location.pathname).toBe("/login");
  });
});
