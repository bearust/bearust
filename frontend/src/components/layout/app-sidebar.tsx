import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarRail,
} from "@/components/ui/sidebar";
import { ShieldCheck } from "lucide-react";
import { sidebarData } from "./nav-data";
import { NavGroup } from "./nav-group";
import { NavUser } from "./nav-user";
import { useTranslation } from "react-i18next";

export function AppSidebar({ aiEnabled = true }: { aiEnabled?: boolean }) {
  const { t } = useTranslation();
  const navGroups = sidebarData.navGroups.map((group) => ({
    ...group,
    items: group.items.filter((item) => aiEnabled || item.title !== "AI Advisor"),
  }));
  return (
    <Sidebar collapsible="icon" variant="inset">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" className="cursor-default hover:bg-transparent">
              <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
                <ShieldCheck className="size-4" />
              </div>
              <div className="grid flex-1 text-start text-sm leading-tight group-data-[collapsible=icon]:hidden">
                <span className="truncate font-semibold">{t("shell.brand")}</span>
                <span className="truncate text-xs">{t("shell.tagline")}</span>
              </div>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        {navGroups.map((group) => (
          <NavGroup key={group.title} {...group} />
        ))}
      </SidebarContent>
      <SidebarFooter>
        <NavUser />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
