import { create } from "zustand";
import type { User } from "@/api";

interface AuthState {
  user: User | null;
  aiAdvisorEnabled: boolean;
  setUser: (user: User | null) => void;
  setAiAdvisorEnabled: (enabled: boolean) => void;
  reset: () => void;
}

export const useAuthStore = create<AuthState>()((set) => ({
  user: null,
  aiAdvisorEnabled: false,
  setUser: (user) => set({ user }),
  setAiAdvisorEnabled: (aiAdvisorEnabled) => set({ aiAdvisorEnabled }),
  reset: () => set({ user: null, aiAdvisorEnabled: false }),
}));
