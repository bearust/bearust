import { createFileRoute } from "@tanstack/react-router";
import { AiAdvisor } from "@/features/ai-advisor";

export const Route = createFileRoute("/_authenticated/ai-advisor")({
  component: AiAdvisor,
});
