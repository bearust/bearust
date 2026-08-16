import {
  Activity,
  BarChart3,
  Blocks,
  Cable,
  FileClock,
  LayoutDashboard,
  Network,
  Settings,
  ShieldCheck,
  Sparkles,
  Users,
} from "lucide-react";
import type { ElementType } from "react";
import type { NavGroup, NavItem, SidebarData } from "./types";

export const sidebarData: SidebarData = {
  navGroups: [
    {
      title: "General",
      items: [
        { title: "Dashboard", url: "/", icon: LayoutDashboard },
        { title: "Operations", url: "/operations", icon: Activity },
        { title: "Proxy Hosts", url: "/proxy-hosts", icon: Cable },
        { title: "Load Balancer", url: "/load-balancer", icon: Network },
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
        { title: "Settings", url: "/settings", icon: Settings },
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

const NAV_TRANSLATION_KEYS: Record<string, string> = {
  General: "shell.general",
  Protection: "shell.protection",
  Administration: "shell.administration",
  Dashboard: "shell.dashboard",
  Overview: "shell.overview",
  Operations: "shell.operations",
  "Proxy Hosts": "shell.proxyHosts",
  "Proxy hosts": "shell.proxyHosts",
  "Load Balancer": "shell.loadBalancer",
  "Load balancer": "shell.loadBalancer",
  Analytics: "shell.analytics",
  Cluster: "shell.cluster",
  Security: "shell.security",
  "WAF rules": "shell.wafRules",
  "Bot protection": "shell.botProtection",
  "Rate limiting": "shell.rateLimiting",
  "AI Advisor": "shell.aiAdvisor",
  Plugins: "shell.plugins",
  "Users & Roles": "shell.usersRoles",
  "Audit Log": "shell.auditLog",
  Settings: "shell.settings",
};

export function navTranslationKey(title: string) {
  return NAV_TRANSLATION_KEYS[title] ?? title;
}
