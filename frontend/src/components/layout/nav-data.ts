import type { LucideIcon } from "lucide-react";
import { Cable, Sparkles, ShieldCheck, BarChart3, Users, ScrollText } from "lucide-react";

export type NavItem = {
  title: string;
  labelKey: string;
  url: string;
  icon: LucideIcon;
  adminOnly?: boolean;
};

export const NAV_ITEMS: NavItem[] = [
  { title: "Proxy Hosts", labelKey: "nav.proxyHosts", url: "/", icon: Cable },
  { title: "AI Advisor", labelKey: "nav.aiAdvisor", url: "/ai-advisor", icon: Sparkles },
  { title: "Security", labelKey: "nav.security", url: "/security", icon: ShieldCheck },
  { title: "Analytics", labelKey: "nav.analytics", url: "/analytics", icon: BarChart3 },
  { title: "Users & Roles", labelKey: "nav.users", url: "/users", icon: Users, adminOnly: true },
  { title: "Audit Log", labelKey: "nav.audit", url: "/audit-log", icon: ScrollText },
];
