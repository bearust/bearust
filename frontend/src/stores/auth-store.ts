import { create } from "zustand";
import type { ThemeMode, User } from "@/api";

interface AuthState {
  user: User | null;
  theme: ThemeMode | null;
  themeLoaded: boolean;
  aiAdvisorEnabled: boolean;
  setUser: (user: User | null) => void;
  setTheme: (theme: ThemeMode | null) => void;
  setAiAdvisorEnabled: (enabled: boolean) => void;
  reset: () => void;
}

export const useAuthStore = create<AuthState>()((set) => ({
  user: null,
  theme: null,
  themeLoaded: false,
  aiAdvisorEnabled: false,
  setUser: (user) => set({ user }),
  setTheme: (theme) => set({ theme, themeLoaded: true }),
  setAiAdvisorEnabled: (aiAdvisorEnabled) => set({ aiAdvisorEnabled }),
  reset: () => set({ user: null, theme: null, themeLoaded: false, aiAdvisorEnabled: false }),
}));
