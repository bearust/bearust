import { useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ChevronsUpDown, LogOut } from "lucide-react";
import { api } from "@/api";
import { useAuthStore } from "@/stores/auth-store";
import { useTheme, type ThemeMode } from "@/theme";
import { useLocalePreference, normalizeLocale } from "@/i18n";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from "@/components/ui/sidebar";

export function NavUser() {
  const { t } = useTranslation();
  const { isMobile } = useSidebar();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const user = useAuthStore((s) => s.user);
  const { mode, setMode } = useTheme();
  const { locale, setLocale } = useLocalePreference();
  if (!user) return null;
  const initials = user.email.slice(0, 2).toUpperCase();

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg">
              <Avatar className="h-8 w-8 rounded-lg">
                <AvatarFallback className="rounded-lg">{initials}</AvatarFallback>
              </Avatar>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-medium">{user.email}</span>
                <span className="truncate text-xs text-muted-foreground">{user.role}</span>
              </div>
              <ChevronsUpDown className="ml-auto size-4" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent side={isMobile ? "bottom" : "right"} align="end" className="min-w-56">
            <DropdownMenuLabel className="font-normal">
              <div className="text-sm font-medium">{user.email}</div>
              <div className="text-xs text-muted-foreground">{user.role}</div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <div className="px-2 py-1.5 text-xs text-muted-foreground">{t("theme.label")}</div>
            <div className="px-2 pb-2">
              <select
                aria-label={t("theme.label")}
                value={mode}
                onChange={(e) => setMode(e.target.value as ThemeMode)}
                className="w-full rounded-md border border-input bg-background px-2 py-1.5 text-sm"
              >
                <option value="system">{t("theme.system")}</option>
                <option value="light">{t("theme.light")}</option>
                <option value="dark">{t("theme.dark")}</option>
              </select>
            </div>
            <div className="px-2 py-1.5 text-xs text-muted-foreground">{t("language.label")}</div>
            <div className="px-2 pb-2">
              <select
                aria-label={t("language.label")}
                value={locale}
                onChange={(e) => void setLocale(normalizeLocale(e.target.value))}
                className="w-full rounded-md border border-input bg-background px-2 py-1.5 text-sm"
              >
                <option value="en">{t("language.options.en")}</option>
                <option value="id">{t("language.options.id")}</option>
                <option value="ja">{t("language.options.ja")}</option>
              </select>
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => {
                void api.logout().catch(() => undefined).finally(() => {
                  useAuthStore.getState().reset();
                  queryClient.removeQueries({ queryKey: ["me"] });
                  void navigate({ to: "/login" });
                });
              }}
            >
              <LogOut />
              {t("auth.signOut")}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
