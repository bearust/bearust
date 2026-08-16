import { Link, useRouterState } from "@tanstack/react-router";
import { Menu } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { useTranslation } from "react-i18next";
import { navTranslationKey } from "./nav-data";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const links = [
  { title: "Overview", href: "/" },
  { title: "Operations", href: "/operations" },
  { title: "Proxy hosts", href: "/proxy-hosts" },
  { title: "Load balancer", href: "/load-balancer" },
  { title: "Security", href: "/security" },
  { title: "Analytics", href: "/analytics" },
  { title: "Cluster", href: "/cluster" },
  { title: "Plugins", href: "/plugins" },
];

export function TopNav({ className }: { className?: string }) {
  const { t } = useTranslation();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="icon" variant="outline" className="md:size-8 2xl:hidden">
            <Menu />
            <span className="sr-only">{t("shell.openSectionNavigation")}</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent side="bottom" align="start">
          {links.map((link) => (
            <DropdownMenuItem key={link.href} asChild>
              <Link to={link.href} className={pathname !== link.href ? "text-muted-foreground" : ""}>
                {t(navTranslationKey(link.title))}
              </Link>
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
      <nav className={cn("hidden items-center gap-4 2xl:flex 2xl:gap-6", className)} aria-label={t("shell.primaryNavigation")}>
        {links.map((link) => (
          <Link
            key={link.href}
            to={link.href}
            className={cn(
              "text-sm font-medium transition-colors hover:text-primary",
              pathname !== link.href && "text-muted-foreground",
            )}
          >
            {t(navTranslationKey(link.title))}
          </Link>
        ))}
      </nav>
    </>
  );
}
