import { describe, expect, it, afterEach } from "vitest";
import { useAuthStore } from "./auth-store";

const admin = { id: 1, email: "admin@example.com", role: "admin", disabled: false } as const;

describe("useAuthStore", () => {
  afterEach(() => {
    useAuthStore.getState().reset();
  });

  it("starts with no user", () => {
    expect(useAuthStore.getState().user).toBeNull();
  });

  it("setUser stores the user", () => {
    useAuthStore.getState().setUser(admin);
    expect(useAuthStore.getState().user).toEqual(admin);
  });

  it("reset clears the user", () => {
    useAuthStore.getState().setUser(admin);
    useAuthStore.getState().reset();
    expect(useAuthStore.getState().user).toBeNull();
  });
});
