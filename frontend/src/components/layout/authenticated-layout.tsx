import { Outlet } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { getCookie } from "@/lib/cookies";
import { useAuthStore } from "@/stores/auth-store";
import { LocalePreferenceProvider } from "@/i18n";
import { useRealtimeUpdates } from "@/realtime";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { Bell } from "lucide-react";
import { Button } from "@/components/ui/button";
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
  const queryClient = useQueryClient();
  useRealtimeUpdates({
    sessions: () => void queryClient.invalidateQueries({ queryKey: ["me"] }),
  });
  return (
    <LocalePreferenceProvider accountLocale={user?.preferred_locale}>
      <SidebarProvider defaultOpen={defaultOpen}>
        <SkipToMain />
        <AppSidebar />
        <SidebarInset className="@container/content min-h-svh">
          <Header fixed>
            <TopNav className="me-auto" />
            <Search />
            <ThemeSwitch />
            <Button variant="ghost" size="icon" className="relative hidden rounded-full md:inline-flex" aria-label="View notifications">
              <Bell className="size-[1.15rem]" />
              <span className="absolute right-1 top-1 size-1.5 rounded-full bg-primary" aria-hidden="true" />
            </Button>
            <ProfileDropdown />
          </Header>
          <Outlet />
        </SidebarInset>
      </SidebarProvider>
    </LocalePreferenceProvider>
  );
}
