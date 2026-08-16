import { useEffect, useRef } from "react";

export function useRealtimeRefresh(kinds: readonly string[], refresh: () => unknown | Promise<unknown>) {
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;
  const key = kinds.join("|");
  useEffect(() => {
    const listener = (event: Event) => {
      const kind = (event as CustomEvent<string>).detail;
      if (!kinds.includes(kind)) return;
      void Promise.resolve(refreshRef.current()).catch(() => undefined);
    };
    window.addEventListener("bearust:realtime", listener);
    return () => window.removeEventListener("bearust:realtime", listener);
  }, [key]);
}
