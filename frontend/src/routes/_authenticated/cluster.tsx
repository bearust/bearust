import { createFileRoute } from "@tanstack/react-router";
import { Cluster } from "@/features/cluster";

export const Route = createFileRoute("/_authenticated/cluster")({ component: Cluster });
