// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { toast } from "sonner";
import { useOperationalNotifications } from "./notification-preferences";

function Harness({ userId }: { userId: number }) {
  useOperationalNotifications(userId);
  return null;
}

beforeEach(() => {
  const values = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

it("uses saved account preferences when operational events arrive", async () => {
  localStorage.setItem("bearust.notifications.v1.7", JSON.stringify({ security: false, certificates: true, cluster: true }));
  const notify = vi.spyOn(toast, "info");
  const root = createRoot(document.body);
  await act(async () => root.render(<Harness userId={7} />));
  await act(async () => {
    for (const kind of ["security.changed", "certificates.changed", "cluster.changed", "analytics.changed"]) {
      window.dispatchEvent(new CustomEvent("bearust:realtime", { detail: kind }));
    }
  });
  expect(notify.mock.calls.map(([message]) => message)).toEqual(["Certificates updated", "Cluster status updated"]);
  // Saved choices take effect without restarting the realtime connection.
  localStorage.setItem("bearust.notifications.v1.7", JSON.stringify({ security: true, certificates: false, cluster: false }));
  await act(async () => window.dispatchEvent(new CustomEvent("bearust:realtime", { detail: "security.changed" })));
  expect(notify).toHaveBeenLastCalledWith("Security policy updated", { id: "bearust-security" });
  await act(async () => root.unmount());
});

it("does not reuse one account's notification preferences for another", async () => {
  localStorage.setItem("bearust.notifications.v1.7", JSON.stringify({ security: false, certificates: false, cluster: false }));
  const notify = vi.spyOn(toast, "info");
  const root = createRoot(document.body);
  await act(async () => root.render(<Harness userId={8} />));
  await act(async () => window.dispatchEvent(new CustomEvent("bearust:realtime", { detail: "security.changed" })));
  expect(notify).toHaveBeenCalledWith("Security policy updated", { id: "bearust-security" });
  await act(async () => root.unmount());
});
