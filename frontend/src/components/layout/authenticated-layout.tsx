import { useEffect } from "react";
import { Outlet, useNavigate } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api";
import { getCookie } from "@/lib/cookies";
import { DEMO_MODE } from "@/lib/demo";
import { useAuthStore } from "@/stores/auth-store";
import { LocalePreferenceProvider } from "@/i18n";
import { useRealtimeUpdates } from "@/realtime";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";
import { Header } from "./header";
import { TopNav } from "./top-nav";
import { Search } from "@/components/search";
import { ThemeSwitch } from "@/components/theme-switch";
import { ProfileDropdown } from "@/components/profile-dropdown";
import { SkipToMain } from "@/components/skip-to-main";

export function AuthenticatedLayout() {
  const defaultOpen = getCookie("sidebar_state") !== "false";
  const user = useAuthStore((s) => s.user);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const session = useQuery({ queryKey: ["me"], queryFn: api.me, enabled: !DEMO_MODE, staleTime: 30_000 });
  const themePreference = useQuery({ queryKey: ["theme-preference"], queryFn: api.themePreference, enabled: !DEMO_MODE, staleTime: Infinity });
  const advisorStatus = useQuery({ queryKey: ["ai-advisor", "status"], queryFn: api.aiAdvisorStatus, enabled: !DEMO_MODE, staleTime: 30_000 });
  useEffect(() => {
    if (session.data) useAuthStore.getState().setUser(session.data);
    if (themePreference.data) useAuthStore.getState().setTheme(themePreference.data.preferred_theme);
    useAuthStore.getState().setAiAdvisorEnabled(DEMO_MODE || advisorStatus.data?.enabled === true);
    if (session.error && (session.error as { status?: number }).status === 401) {
      useAuthStore.getState().reset();
      void navigate({ to: "/login" });
    }
  }, [advisorStatus.data?.enabled, navigate, session.data, session.error, themePreference.data]);
  useRealtimeUpdates({
    sessions: () => void queryClient.invalidateQueries({ queryKey: ["me"] }),
    aiAdvisor: () => void queryClient.invalidateQueries({ queryKey: ["ai-advisor", "status"] }),
  });
  return (
    <LocalePreferenceProvider accountLocale={user?.preferred_locale}>
      <SidebarProvider defaultOpen={defaultOpen}>
        <SkipToMain />
        <AppSidebar aiEnabled={DEMO_MODE || advisorStatus.data?.enabled === true} />
        <SidebarInset className="@container/content min-h-svh">
          <Header fixed>
            <TopNav className="me-auto" />
            <Search />
            <ThemeSwitch />
            <ProfileDropdown />
          </Header>
          <Outlet />
        </SidebarInset>
      </SidebarProvider>
    </LocalePreferenceProvider>
  );
}
