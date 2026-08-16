import { createFileRoute } from "@tanstack/react-router";
import { LoadBalancer } from "@/features/load-balancer";

export const Route = createFileRoute("/_authenticated/load-balancer")({
  component: LoadBalancer,
});
