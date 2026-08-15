import { useRouterState } from "@tanstack/react-router";
import { useAuthStore } from "@/stores/auth-store";
import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarRail } from "@/components/ui/sidebar";
import { NavGroup } from "./nav-group";
import { NavUser } from "./nav-user";

export function AppSidebar() {
  const user = useAuthStore((s) => s.user);
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <div className="flex items-center gap-2.5 px-2 py-1.5">
          <span aria-hidden="true" className="inline-block h-2.5 w-2.5 rounded-full bg-primary" />
          <span className="font-semibold tracking-tight text-primary">Bearust</span>
        </div>
      </SidebarHeader>
      <SidebarContent>
        <NavGroup isAdmin={user?.role === "admin"} activePath={pathname} />
      </SidebarContent>
      <SidebarFooter>
        <NavUser />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
