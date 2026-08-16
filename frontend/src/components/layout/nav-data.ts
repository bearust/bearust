import {
  Activity,
  BarChart3,
  Blocks,
  Cable,
  FileClock,
  LayoutDashboard,
  MessagesSquare,
  Network,
  ShieldCheck,
  Sparkles,
  Users,
} from "lucide-react";
import type { ElementType } from "react";
import type { NavGroup, NavItem, SidebarData } from "./types";

export const sidebarData: SidebarData = {
  user: {
    name: "Rizalord",
    email: "admin@bearust.local",
    avatar: "",
  },
  teams: [
    {
      name: "BeaRust Control Plane",
      logo: ShieldCheck,
      plan: "Self-hosted edge security",
    },
    {
      name: "Production Cluster",
      logo: Network,
      plan: "3 nodes · healthy",
    },
    {
      name: "Homelab Sandbox",
      logo: Cable,
      plan: "Development workspace",
    },
  ],
  navGroups: [
    {
      title: "General",
      items: [
        { title: "Dashboard", url: "/", icon: LayoutDashboard },
        { title: "Proxy Hosts", url: "/proxy-hosts", icon: Cable },
        { title: "Analytics", url: "/analytics", icon: BarChart3 },
        { title: "Cluster", url: "/cluster", icon: Network },
      ],
    },
    {
      title: "Protection",
      items: [
        {
          title: "Security",
          icon: ShieldCheck,
          items: [
            { title: "WAF rules", url: "/security?tab=waf", icon: ShieldCheck },
            { title: "Bot protection", url: "/security?tab=bot", icon: Activity },
            { title: "Rate limiting", url: "/security?tab=rate", icon: Activity },
          ],
        },
        { title: "AI Advisor", url: "/ai-advisor", icon: Sparkles },
        { title: "Plugins", url: "/plugins", icon: Blocks },
      ],
    },
    {
      title: "Administration",
      items: [
        { title: "Users & Roles", url: "/users", icon: Users },
        { title: "Audit Log", url: "/audit-log", icon: FileClock },
        { title: "Support inbox", url: "/support", icon: MessagesSquare, badge: "3" },
      ],
    },
  ],
};

function flattenItems(groups: NavGroup[]): NavItem[] {
  return groups.flatMap((group) =>
    group.items.flatMap((item) => (item.items ? item.items : item)),
  );
}

export type FlatNavItem = {
  title: string;
  url: string;
  icon?: ElementType;
  badge?: string;
};

export const NAV_ITEMS: FlatNavItem[] = flattenItems(sidebarData.navGroups).filter(
  (item): item is NavItem & { url: string } => "url" in item,
);
