import { createFileRoute, redirect } from "@tanstack/react-router";
import { api } from "@/api";
import { useAuthStore } from "@/stores/auth-store";
import { AuthenticatedLayout } from "@/components/layout/authenticated-layout";
import { DEMO_MODE, DEMO_USER } from "@/lib/demo";

export const Route = createFileRoute("/_authenticated")({
  beforeLoad: async ({ context }) => {
    if (DEMO_MODE) {
      useAuthStore.getState().setUser(DEMO_USER);
      return { user: DEMO_USER };
    }
    const status = await context.queryClient.fetchQuery({
      queryKey: ["setup-status"],
      queryFn: api.status,
      staleTime: Infinity,
    });
    if (!status.initialized) throw redirect({ to: "/setup" });

    try {
      const user = await context.queryClient.ensureQueryData({
        queryKey: ["me"],
        queryFn: api.me,
        staleTime: 30_000,
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
