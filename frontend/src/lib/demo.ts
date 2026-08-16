import type { User } from "@/api";

export const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === "true";

export const DEMO_USER: User = {
  id: 1,
  email: "admin@bearust.local",
  role: "admin",
  disabled: false,
};
