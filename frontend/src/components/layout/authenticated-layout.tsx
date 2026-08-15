import { Outlet } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { getCookie } from "@/lib/cookies";
import { useAuthStore } from "@/stores/auth-store";
import { LocalePreferenceProvider } from "@/i18n";
import { useRealtimeUpdates } from "@/realtime";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";

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
        <AppSidebar />
        <SidebarInset>
          <Outlet />
        </SidebarInset>
      </SidebarProvider>
    </LocalePreferenceProvider>
  );
}
