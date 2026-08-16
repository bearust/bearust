import { createFileRoute } from "@tanstack/react-router";
import { ProxyHosts } from "@/features/proxy-hosts";

export const Route = createFileRoute("/_authenticated/proxy-hosts")({
  component: ProxyHosts,
});
