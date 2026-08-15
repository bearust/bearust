import { Link } from "@tanstack/react-router";
import { NAV_ITEMS } from "./nav-data";
import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";

export function NavGroup({ isAdmin, activePath }: { isAdmin: boolean; activePath: string }) {
  return (
    <SidebarGroup>
      <SidebarGroupContent>
        <SidebarMenu>
          {NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin).map((item) => (
            <SidebarMenuItem key={item.url}>
              <SidebarMenuButton asChild isActive={activePath === item.url}>
                <Link to={item.url}>
                  <item.icon />
                  <span>{item.title}</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}
