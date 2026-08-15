import { create } from "zustand";
import type { User } from "@/api";

interface AuthState {
  user: User | null;
  setUser: (user: User | null) => void;
  reset: () => void;
}

export const useAuthStore = create<AuthState>()((set) => ({
  user: null,
  setUser: (user) => set({ user }),
  reset: () => set({ user: null }),
}));
