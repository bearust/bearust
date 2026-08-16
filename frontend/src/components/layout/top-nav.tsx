import { Link, useRouterState } from "@tanstack/react-router";
import { Menu } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const links = [
  { title: "Overview", href: "/" },
  { title: "Proxy hosts", href: "/proxy-hosts" },
  { title: "Security", href: "/security" },
  { title: "Analytics", href: "/analytics" },
];

export function TopNav({ className }: { className?: string }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="icon" variant="outline" className="md:size-8 lg:hidden">
            <Menu />
            <span className="sr-only">Open section navigation</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent side="bottom" align="start">
          {links.map((link) => (
            <DropdownMenuItem key={link.href} asChild>
              <Link to={link.href} className={pathname !== link.href ? "text-muted-foreground" : ""}>
                {link.title}
              </Link>
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
      <nav className={cn("hidden items-center gap-4 lg:flex xl:gap-6", className)} aria-label="Primary">
        {links.map((link) => (
          <Link
            key={link.href}
            to={link.href}
            className={cn(
              "text-sm font-medium transition-colors hover:text-primary",
              pathname !== link.href && "text-muted-foreground",
            )}
          >
            {link.title}
          </Link>
        ))}
      </nav>
    </>
  );
}
