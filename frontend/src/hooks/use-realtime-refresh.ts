import { useEffect, useRef } from "react";

export function useRealtimeRefresh(kinds: readonly string[], refresh: () => unknown | Promise<unknown>) {
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;
  const key = kinds.join("|");
  useEffect(() => {
    const reload = () => {
      void Promise.resolve().then(() => refreshRef.current()).catch(() => undefined);
    };
    const listener = (event: Event) => {
      const kind = (event as CustomEvent<string>).detail;
      if (!kinds.includes(kind)) return;
      reload();
    };
    window.addEventListener("bearust:realtime", listener);
    window.addEventListener("bearust:realtime-resync", reload);
    return () => {
      window.removeEventListener("bearust:realtime", listener);
      window.removeEventListener("bearust:realtime-resync", reload);
    };
  }, [key]);
}
