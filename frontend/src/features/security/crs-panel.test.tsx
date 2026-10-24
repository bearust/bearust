// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { CrsPanel } from "./crs-panel";
import { api, type SecLangStatus } from "@/api";

let root: Root;
afterEach(async () => {
  if (root) await act(async () => root.unmount());
  vi.restoreAllMocks();
  document.body.innerHTML = "";
});

const status: SecLangStatus = { crs_enabled: false, paranoia_level: 1, inbound_threshold: 5, custom_rules: "", updated_at: "", crs_version: "4.7.0", active_rules: 0 };

it("saves CRS settings and shows rule compilation errors", async () => {
  vi.spyOn(api, "wafSecLang").mockResolvedValue(status);
  const update = vi.spyOn(api, "updateWafSecLang")
    .mockRejectedValueOnce(Object.assign(new Error("line 1: custom.conf: unsupported operator @nope"), { status: 400, code: "invalid_rules" }))
    .mockResolvedValueOnce({ ...status, crs_enabled: true, paranoia_level: 2, active_rules: 506 });
  root = createRoot(document.body);
  await act(async () => root.render(<CrsPanel canWrite />));
  const checkbox = document.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
  await act(async () => checkbox.click());
  const select = document.querySelector<HTMLSelectElement>("#crs-paranoia")!;
  await act(async () => {
    select.value = "2";
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });
  const form = document.querySelector("form")!;
  await act(async () => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
  expect(document.querySelector('[role="alert"]')?.textContent).toContain("unsupported operator");
  await act(async () => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
  expect(update).toHaveBeenLastCalledWith({ crs_enabled: true, paranoia_level: 2, inbound_threshold: 5, custom_rules: "" });
  expect(document.body.textContent).toContain("506 rules active · CRS 4.7.0");
});
