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
    vi.spyOn(api, "setup").mockRejectedValue(
      Object.assign(new Error("Invalid setup token"), { status: 400 }),
    );
    const { element } = await renderRoute([SetupRoute], "/setup");
    const form = element.querySelector("form") as HTMLFormElement;
    expect(form).toBeTruthy();
    await act(async () => {
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(element.textContent).toContain("Invalid setup token");
  });
});
