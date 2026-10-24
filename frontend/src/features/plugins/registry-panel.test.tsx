// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { RegistryPanel } from "./registry-panel";
import { api } from "@/api";

let root: Root;
afterEach(async () => {
  if (root) await act(async () => root.unmount());
  vi.restoreAllMocks();
  vi.useRealTimers();
  document.body.innerHTML = "";
});

it("shows index trust and installs or upgrades entries", async () => {
  vi.useFakeTimers();
  vi.spyOn(api, "pluginRegistry").mockResolvedValue({
    index_signed: true,
    entries: [
      { id: "geo-tagger", display_name: "Geo tagger", description: "Adds geo headers", version: "1.0.0", signed: true, installed_version: null, update_available: false },
      { id: "health-ok", display_name: "Health", description: "Fixture", version: "2.0.0", signed: true, installed_version: "1.0.0", update_available: true },
    ],
  });
  const install = vi.spyOn(api, "installRegistryPlugin").mockResolvedValue({ id: "health-ok", version: "2.0.0", signed: true, index_signed: true });
  const onInstalled = vi.fn();
  root = createRoot(document.body);
  await act(async () => root.render(<RegistryPanel canManage onInstalled={onInstalled} />));
  await act(async () => { vi.advanceTimersByTime(300); });
  expect(document.body.textContent).toContain("Signed index");
  const buttons = [...document.querySelectorAll("button")];
  expect(buttons.map((b) => b.textContent)).toEqual(["Install", "Upgrade to 2.0.0"]);
  await act(async () => buttons[1].click());
  expect(install).toHaveBeenCalledWith("health-ok", true);
  expect(onInstalled).toHaveBeenCalled();
});
