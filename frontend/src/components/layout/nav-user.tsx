import { useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { BadgeCheck, ChevronsUpDown, LogOut, Palette, Languages } from "lucide-react";
import { api } from "@/api";
import { useAuthStore } from "@/stores/auth-store";
import { useTheme, type ThemeMode } from "@/theme";
import { normalizeLocale, useLocalePreference } from "@/i18n";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";

const demoMode = import.meta.env.VITE_DEMO_MODE === "true";

export function NavUser() {
  const { t } = useTranslation();
  const { isMobile } = useSidebar();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const user = useAuthStore((state) => state.user);
  const { mode, setMode } = useTheme();
  const { locale, setLocale } = useLocalePreference();

  if (!user) return null;

  const initials = user.email
    .split("@", 1)[0]
    .split(/[._-]/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  const signOut = () => {
    const finish = () => {
      useAuthStore.getState().reset();
      queryClient.removeQueries({ queryKey: ["me"] });
      void navigate({ to: "/login" });
    };
    if (demoMode) {
      finish();
      return;
    }
    void api.logout().catch(() => undefined).finally(finish);
  };

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              size="lg"
              className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
            >
              <Avatar className="h-8 w-8 rounded-lg">
                <AvatarFallback className="rounded-lg bg-primary text-primary-foreground">
                  {initials}
                </AvatarFallback>
              </Avatar>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-semibold">{user.email.split("@")[0]}</span>
                <span className="truncate text-xs text-muted-foreground">{user.email}</span>
              </div>
              <ChevronsUpDown className="ml-auto size-4" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className="w-(--radix-dropdown-menu-trigger-width) min-w-64 rounded-lg"
            side={isMobile ? "bottom" : "right"}
            align="end"
            sideOffset={4}
          >
            <DropdownMenuLabel className="p-0 font-normal">
              <div className="flex items-center gap-2 px-1 py-1.5 text-left text-sm">
                <Avatar className="h-8 w-8 rounded-lg">
                  <AvatarFallback className="rounded-lg bg-primary text-primary-foreground">
                    {initials}
                  </AvatarFallback>
                </Avatar>
                <div className="grid flex-1 leading-tight">
                  <span className="truncate font-semibold">{user.email.split("@")[0]}</span>
                  <span className="truncate text-xs text-muted-foreground">{user.role}</span>
                </div>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem>
              <BadgeCheck />
              {t("shell.adminWorkspace")}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <div className="space-y-2 px-2 py-2">
              <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
                <Palette className="size-3.5" />
                {t("theme.label")}
              </div>
              <select
                aria-label={t("theme.label")}
                value={mode}
                onChange={(event) => setMode(event.target.value as ThemeMode)}
                className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm outline-none focus:ring-2 focus:ring-ring/50"
              >
                <option value="system">{t("theme.system")}</option>
                <option value="light">{t("theme.light")}</option>
                <option value="dark">{t("theme.dark")}</option>
              </select>
            </div>
            <div className="space-y-2 px-2 py-2">
              <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
                <Languages className="size-3.5" />
                {t("language.label")}
              </div>
              <select
                aria-label={t("language.label")}
                value={locale}
                onChange={(event) => void setLocale(normalizeLocale(event.target.value))}
                className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm outline-none focus:ring-2 focus:ring-ring/50"
              >
                <option value="en">{t("language.options.en")}</option>
                <option value="id">{t("language.options.id")}</option>
                <option value="ja">{t("language.options.ja")}</option>
              </select>
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive" onClick={signOut}>
              <LogOut />
              {t("auth.signOut")}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
