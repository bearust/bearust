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

  it("submits the login form and shows a server error inline", async () => {
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
