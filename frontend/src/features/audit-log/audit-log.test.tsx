// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { AuditLog } from ".";
import { api, type AuditLogPage } from "@/api";

let root: Root;
afterEach(async () => {
  if (root) await act(async () => root.unmount());
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

function page(details: string, actor = "admin@example.com"): AuditLogPage {
  return { items: [{ id: 1, actor, event: "proxy_host_created", details, created_at: "2026-10-01T00:00:00Z" }], page: 1, page_size: 25, total: 1 };
}

it("exports audit fields as text even when user-provided values look like spreadsheet formulas", async () => {
  vi.spyOn(api, "auditLogs").mockResolvedValue(page("\t=1+1", '=HYPERLINK("https://example.test","click")'));
  let downloaded: Blob | undefined;
  vi.stubGlobal("URL", Object.assign(class extends URL {}, {
    createObjectURL: (blob: Blob) => { downloaded = blob; return "blob:audit"; },
    revokeObjectURL: () => {},
  }));
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  root = createRoot(document.body);
  await act(async () => root.render(<AuditLog />));
  const exportButton = [...document.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent === "Export CSV")!;
  await act(async () => exportButton.click());
  const csv = await new Promise<string>((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.readAsText(downloaded!);
  });
  expect(csv).toContain('"\'=HYPERLINK(""https://example.test"",""click"")"');
  expect(csv).toContain('"\'\t=1+1"');
});

it("keeps the latest filtered result when an earlier request finishes afterward", async () => {
  let resolveOld!: (value: AuditLogPage) => void;
  let resolveNew!: (value: AuditLogPage) => void;
  vi.spyOn(api, "auditLogs")
    .mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve; }))
    .mockImplementationOnce(() => new Promise((resolve) => { resolveNew = resolve; }));
  root = createRoot(document.body);
  await act(async () => root.render(<AuditLog />));
  const input = document.querySelector<HTMLInputElement>('[aria-label="Search audit log"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "filtered");
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => resolveNew(page("current-filter-result")));
  await act(async () => resolveOld(page("stale-result")));
  expect(document.body.textContent).toContain("current-filter-result");
  expect(document.body.textContent).not.toContain("stale-result");
});
