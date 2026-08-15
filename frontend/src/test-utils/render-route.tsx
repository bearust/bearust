import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
  type AnyRoute,
} from "@tanstack/react-router";
import { I18nextProvider } from "react-i18next";
import { i18n, initI18n } from "@/i18n";
import { ThemeProvider } from "@/theme";
// Side-effect import: TanStack Router's file-route generator wires each
// `createFileRoute(...)` export's real `path`/`getParentRoute` via
// `Route.update(...)` inside this generated module. Route modules imported
// directly (bypassing routeTree.gen.ts) never receive that wiring on their
// own, so route trees built ad-hoc for isolated route tests need this
// import to run first.
import "@/routeTree.gen";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

export async function renderRoute(routes: AnyRoute[], initialPath: string) {
  await initI18n("en");
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const rootRoute = createRootRoute();
  for (const route of routes) {
    // Route modules built via `createFileRoute(...)` bind their real
    // `getParentRoute` to the app's actual root route only once
    // routeTree.gen.ts has run (see the import above). For an isolated
    // route test we want that route parented under our own throwaway
    // root instead, so re-point it here before building the tree.
    (route as unknown as { options: { getParentRoute: () => AnyRoute } }).options.getParentRoute =
      () => rootRoute;
  }
  const router = createRouter({
    routeTree: rootRoute.addChildren(routes),
    history: createMemoryHistory({ initialEntries: [initialPath] }),
    context: { queryClient },
  });
  // Route components are code-split (autoCodeSplitting), so the initial
  // match's component chunk loads asynchronously. Ensure it (and any other
  // pending loader work) has resolved before mounting, so the first render
  // already has real content instead of an empty/pending shell.
  await router.load();
  const element = document.createElement("div");
  document.body.appendChild(element);
  const root: Root = createRoot(element);
  await act(async () => {
    root.render(
      <QueryClientProvider client={queryClient}>
        <I18nextProvider i18n={i18n}>
          <ThemeProvider>
            <RouterProvider router={router} />
          </ThemeProvider>
        </I18nextProvider>
      </QueryClientProvider>,
    );
  });
  return { element, root, router };
}
