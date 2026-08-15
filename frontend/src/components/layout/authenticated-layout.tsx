import { Outlet } from "@tanstack/react-router";
import { getCookie } from "@/lib/cookies";
import { useAuthStore } from "@/stores/auth-store";
import { LocalePreferenceProvider } from "@/i18n";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";

export function AuthenticatedLayout() {
  const defaultOpen = getCookie("sidebar_state") !== "false";
  const user = useAuthStore((s) => s.user);
  return (
    <LocalePreferenceProvider accountLocale={user?.preferred_locale}>
      <SidebarProvider defaultOpen={defaultOpen}>
        <AppSidebar />
        <SidebarInset>
          <Outlet />
        </SidebarInset>
      </SidebarProvider>
    </LocalePreferenceProvider>
  );
}
