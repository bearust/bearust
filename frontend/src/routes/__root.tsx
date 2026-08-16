import { type QueryClient } from "@tanstack/react-query";
import { createRootRouteWithContext, Link, Outlet } from "@tanstack/react-router";
import { Toaster } from "@/components/ui/sonner";
import { CommandPalette } from "@/components/layout/command-palette";
import { Button } from "@/components/ui/button";
import { useTranslation } from "react-i18next";

// Safety net for any URL the router doesn't recognize (a mistyped path, or
// one of the sidebar nav destinations that doesn't have a route yet) --
// keeps the visitor inside the styled shell with a way back, instead of
// TanStack Router's bare default 404 page.
function NotFound() {
  const { t } = useTranslation();
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 px-4 text-center">
      <h1 className="text-2xl font-semibold text-foreground">{t("shell.pageNotFound")}</h1>
      <p className="text-sm text-muted-foreground">
        {t("shell.pageNotFoundDescription")}
      </p>
      <Button asChild>
        <Link to="/">{t("shell.goHome")}</Link>
      </Button>
    </main>
  );
}

export const Route = createRootRouteWithContext<{
  queryClient: QueryClient;
}>()({
  notFoundComponent: NotFound,
  component: () => (
    <>
      <Outlet />
      <Toaster duration={5000} />
      <CommandPalette />
    </>
  ),
});
