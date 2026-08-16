import { useEffect, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { NAV_ITEMS } from "./nav-data";
import { useAuthStore } from "@/stores/auth-store";
import { useTranslation } from "react-i18next";
import { navTranslationKey } from "./nav-data";

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const { t } = useTranslation();
  const aiAdvisorEnabled = useAuthStore((state) => state.aiAdvisorEnabled);
  const navItems = NAV_ITEMS.filter((item) => aiAdvisorEnabled || item.title !== "AI Advisor");

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    const onOpen = () => setOpen(true);
    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("bearust:open-command", onOpen);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("bearust:open-command", onOpen);
    };
  }, []);

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder={t("shell.commandPlaceholder")} />
      <CommandList>
        <CommandEmpty>{t("shell.noResults")}</CommandEmpty>
        <CommandGroup heading={t("shell.navigation")}>
          {navItems.map((item) => (
            (() => {
              const Icon = item.icon;
              return (
                <CommandItem
                  key={item.url}
                  onSelect={() => {
                    setOpen(false);
                    void navigate({ to: item.url });
                  }}
                >
                  {Icon ? <Icon /> : null}
                  <span>{t(navTranslationKey(item.title))}</span>
                </CommandItem>
              );
            })()
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
