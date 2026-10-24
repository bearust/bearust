import { useEffect, useRef } from "react";
import type { BotChallenge } from "@/api";

type Provider = NonNullable<BotChallenge["captcha"]>["provider"];
type Widget = { render: (element: HTMLElement, options: Record<string, unknown>) => unknown };

const SCRIPTS: Record<Provider, { src: string; global: string }> = {
  turnstile: { src: "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit", global: "turnstile" },
  hcaptcha: { src: "https://js.hcaptcha.com/1/api.js?render=explicit", global: "hcaptcha" },
  recaptcha: { src: "https://www.google.com/recaptcha/api.js?render=explicit", global: "grecaptcha" },
};

/** Load a provider script once and resolve with its widget API. */
function loadProvider(provider: Provider): Promise<Widget> {
  const { src, global } = SCRIPTS[provider];
  const ready = () => {
    const api = (window as unknown as Record<string, Widget | undefined>)[global];
    return api && typeof api.render === "function" ? api : undefined;
  };
  return new Promise((resolve, reject) => {
    if (!document.querySelector(`script[src="${src}"]`)) {
      const script = document.createElement("script");
      script.src = src;
      script.async = true;
      script.onerror = () => reject(new Error("captcha script failed to load"));
      document.head.appendChild(script);
    }
    let attempts = 0;
    const poll = () => {
      const api = ready();
      if (api) resolve(api);
      else if (++attempts > 200) reject(new Error("captcha script unavailable"));
      else setTimeout(poll, 50);
    };
    poll();
  });
}

/** Renders the configured provider's widget and reports its response token. */
export function CaptchaWidget({ provider, siteKey, onToken, onError }: { provider: Provider; siteKey: string; onToken: (token: string) => void; onError: () => void }) {
  const container = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let cancelled = false;
    loadProvider(provider)
      .then((api) => {
        if (cancelled || !container.current) return;
        api.render(container.current, { sitekey: siteKey, callback: (token: string) => onToken(token) });
      })
      .catch(() => {
        if (!cancelled) onError();
      });
    return () => {
      cancelled = true;
    };
  }, [provider, siteKey]);
  return <div ref={container} data-testid="captcha-widget" />;
}
