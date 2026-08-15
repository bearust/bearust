// @vitest-environment jsdom
import { describe, expect, it, afterEach, beforeEach, vi } from "vitest";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { CommandPalette } from "./command-palette";

describe("CommandPalette", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    );
    Element.prototype.scrollIntoView = vi.fn();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("opens on Ctrl+K and lists nav destinations", async () => {
    const element = document.createElement("div");
    document.body.appendChild(element);
    await act(async () => {
      createRoot(element).render(<CommandPalette />);
    });
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "k", ctrlKey: true }));
    });
    expect(document.body.textContent).toContain("Proxy Hosts");
    expect(document.body.textContent).toContain("Audit Log");
  });
});
