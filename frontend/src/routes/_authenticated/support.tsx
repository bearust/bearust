import { createFileRoute } from "@tanstack/react-router";
import { Support } from "@/features/support";

export const Route = createFileRoute("/_authenticated/support")({
  component: Support,
});
