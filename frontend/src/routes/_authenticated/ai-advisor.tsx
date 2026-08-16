import { createFileRoute, redirect } from "@tanstack/react-router";
import { api } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { AiAdvisor } from "@/features/ai-advisor";

export const Route = createFileRoute("/_authenticated/ai-advisor")({
  beforeLoad: async ({ context }) => {
    if (DEMO_MODE) return;
    const status = await context.queryClient.fetchQuery({ queryKey: ["ai-advisor", "status"], queryFn: api.aiAdvisorStatus, staleTime: 30_000 });
    if (!status.enabled) throw redirect({ to: "/analytics" });
  },
  component: AiAdvisor,
});
