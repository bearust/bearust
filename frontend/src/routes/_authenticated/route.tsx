import { createFileRoute, redirect } from "@tanstack/react-router";
import { api } from "@/api";
import { useAuthStore } from "@/stores/auth-store";
import { AuthenticatedLayout } from "@/components/layout/authenticated-layout";

export const Route = createFileRoute("/_authenticated")({
  beforeLoad: async ({ context }) => {
    const status = await context.queryClient.fetchQuery({
      queryKey: ["setup-status"],
      queryFn: api.status,
      staleTime: Infinity,
    });
    if (!status.initialized) throw redirect({ to: "/setup" });

    try {
      const user = await context.queryClient.fetchQuery({
        queryKey: ["me"],
        queryFn: api.me,
      });
      useAuthStore.getState().setUser(user);
      return { user };
    } catch {
      useAuthStore.getState().reset();
      throw redirect({ to: "/login" });
    }
  },
  component: AuthenticatedLayout,
});
