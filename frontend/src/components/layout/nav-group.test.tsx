// @vitest-environment jsdom
import { describe, expect, it, afterEach, beforeEach, vi } from "vitest";
import { act } from "react";
import { createRoot } from "react-dom/client";
import type { ReactNode } from "react";
import { NavGroup } from "./nav-group";
import { SidebarProvider } from "@/components/ui/sidebar";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ to, children }: { to: string; children: ReactNode }) => <a href={to}>{children}</a>,
}));

describe("NavGroup", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "matchMedia",
      vi.fn(() => ({
        matches: false,
        media: "",
        addEventListener: () => {},
        removeEventListener: () => {},
      })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("hides admin-only items for non-admins", async () => {
    const element = document.createElement("div");
    document.body.appendChild(element);
    await act(async () => {
      createRoot(element).render(
        <SidebarProvider>
          <NavGroup isAdmin={false} activePath="/" />
        </SidebarProvider>,
      );
    });
    expect(element.textContent).not.toContain("Users & Roles");
    expect(element.textContent).toContain("Proxy Hosts");
  });

  it("shows admin-only items for admins", async () => {
    const element = document.createElement("div");
    document.body.appendChild(element);
    await act(async () => {
      createRoot(element).render(
        <SidebarProvider>
          <NavGroup isAdmin={true} activePath="/" />
        </SidebarProvider>,
      );
    });
    expect(element.textContent).toContain("Users & Roles");
  });
});
