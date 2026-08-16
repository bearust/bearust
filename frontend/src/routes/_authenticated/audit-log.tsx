import { createFileRoute } from "@tanstack/react-router";
import { AuditLog } from "@/features/audit-log";

export const Route = createFileRoute("/_authenticated/audit-log")({
  component: AuditLog,
});
