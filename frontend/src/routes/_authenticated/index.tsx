import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Header } from "@/components/layout/header";

export const Route = createFileRoute("/_authenticated/")({
  component: ProxyHostsPlaceholder,
});

function ProxyHostsPlaceholder() {
  const { t } = useTranslation();
  return (
    <>
      <Header>
        <h1 className="text-lg font-semibold">{t("nav.proxyHosts")}</h1>
      </Header>
      <div className="p-6 text-sm text-muted-foreground">
        {t("nav.proxyHosts")} — not yet ported to the new shell.
      </div>
    </>
  );
}
