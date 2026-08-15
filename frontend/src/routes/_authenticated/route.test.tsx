// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { api } from "@/api";
import { useAuthStore } from "@/stores/auth-store";
import { renderRoute } from "@/test-utils/render-route";
import { Route as AuthenticatedRoute } from "./route";
import { createRoute } from "@tanstack/react-router";

const admin = { id: 1, email: "admin@example.com", role: "admin", disabled: false } as const;

const childRoute = createRoute({
  getParentRoute: () => AuthenticatedRoute,
  path: "/",
  component: () => <p>authenticated home</p>,
});

describe("_authenticated route guard", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    useAuthStore.getState().reset();
    document.body.innerHTML = "";
  });

  it("renders children and syncs the auth store when a session exists", async () => {
    vi.spyOn(api, "status").mockResolvedValue({ initialized: true });
    vi.spyOn(api, "me").mockResolvedValue(admin);
    const { element } = await renderRoute([AuthenticatedRoute.addChildren([childRoute])], "/");
    expect(element.textContent).toContain("authenticated home");
    expect(useAuthStore.getState().user).toEqual(admin);
  });

  it("redirects to /login when there is no session", async () => {
    vi.spyOn(api, "status").mockResolvedValue({ initialized: true });
    vi.spyOn(api, "me").mockRejectedValue(Object.assign(new Error("unauthorized"), { status: 401 }));
    const { router } = await renderRoute([AuthenticatedRoute.addChildren([childRoute])], "/");
    expect(router.state.location.pathname).toBe("/login");
  });

  it("redirects to /setup when the backend has no admin yet", async () => {
    vi.spyOn(api, "status").mockResolvedValue({ initialized: false });
    const meSpy = vi.spyOn(api, "me");
    const { router } = await renderRoute([AuthenticatedRoute.addChildren([childRoute])], "/");
    expect(router.state.location.pathname).toBe("/setup");
    expect(meSpy).not.toHaveBeenCalled();
  });
});
