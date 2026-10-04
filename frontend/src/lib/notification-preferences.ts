import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

export type NotificationPreferences = { security: boolean; certificates: boolean; cluster: boolean };
const DEFAULTS: NotificationPreferences = { security: true, certificates: true, cluster: true };
const storageKey = (userId: number) => `bearust.notifications.v1.${userId}`;

export function readNotificationPreferences(userId: number | undefined): NotificationPreferences {
  if (userId === undefined) return { ...DEFAULTS };
  try {
    const saved: unknown = JSON.parse(window.localStorage.getItem(storageKey(userId)) ?? "null");
    if (!saved || typeof saved !== "object") return { ...DEFAULTS };
    const values = saved as Partial<NotificationPreferences>;
    return {
      security: typeof values.security === "boolean" ? values.security : DEFAULTS.security,
      certificates: typeof values.certificates === "boolean" ? values.certificates : DEFAULTS.certificates,
      cluster: typeof values.cluster === "boolean" ? values.cluster : DEFAULTS.cluster,
    };
  } catch {
    return { ...DEFAULTS };
  }
}

export function saveNotificationPreferences(userId: number | undefined, preferences: NotificationPreferences): boolean {
  if (userId === undefined) return false;
  try {
    window.localStorage.setItem(storageKey(userId), JSON.stringify(preferences));
    return true;
  } catch {
    return false;
  }
}

const NOTIFICATION_EVENTS: Record<string, keyof NotificationPreferences> = {
  "security.changed": "security",
  "waf.changed": "security",
  "bot.changed": "security",
  "rate_limit.changed": "security",
  "certificates.changed": "certificates",
  "cluster.changed": "cluster",
};
const MESSAGE_KEYS = {
  security: "settings.securityChanged",
  certificates: "settings.certificatesChanged",
  cluster: "settings.clusterChanged",
};

export function useOperationalNotifications(userId: number | undefined) {
  const { t } = useTranslation();
  useEffect(() => {
    if (userId === undefined) return;
    const listener = (event: Event) => {
      const category = NOTIFICATION_EVENTS[(event as CustomEvent<string>).detail];
      if (category && readNotificationPreferences(userId)[category]) {
        toast.info(t(MESSAGE_KEYS[category]), { id: `bearust-${category}` });
      }
    };
    window.addEventListener("bearust:realtime", listener);
    return () => window.removeEventListener("bearust:realtime", listener);
  }, [t, userId]);
}
