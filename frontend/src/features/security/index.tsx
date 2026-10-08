import { useEffect, useState, type FormEvent } from "react";
import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import {
  Activity,
  Bot,
  Check,
  Download,
  FilePlus2,
  Globe2,
  LockKeyhole,
  Plus,
  RefreshCw,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  Upload,
} from "lucide-react";
import {
  api,
  type BotConfig,
  type BotMode,
  type IpSecurityAction,
  type IpSecurityRule,
  type RateLimitAction,
  type RateLimitConfig,
  type RateLimitKeyScope,
  type TrustedCrawler,
  type WafAction,
  type WafConfig,
  type WafFeedback,
  type WafMode,
  type WafRule,
} from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { useAuthStore } from "@/stores/auth-store";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const demoWafConfig: WafConfig = {
  mode: "block",
  updated_at: "2026-08-16T09:42:00Z",
};
const demoRules: WafRule[] = [
  {
    id: 1,
    name: "SQL injection signatures",
    source: "OWASP CRS",
    category: "sqli",
    severity: "high",
    enabled: true,
    action: "block",
    matcher_json: "{}",
    created_at: "2026-07-01T00:00:00Z",
    updated_at: "2026-08-16T00:00:00Z",
  },
  {
    id: 2,
    name: "Cross-site scripting",
    source: "OWASP CRS",
    category: "xss",
    severity: "high",
    enabled: true,
    action: "block",
    matcher_json: "{}",
    created_at: "2026-07-01T00:00:00Z",
    updated_at: "2026-08-16T00:00:00Z",
  },
  {
    id: 3,
    name: "Path traversal",
    source: "Bearust semantic",
    category: "path_traversal",
    severity: "medium",
    enabled: true,
    action: "log",
    matcher_json: "{}",
    created_at: "2026-07-01T00:00:00Z",
    updated_at: "2026-08-16T00:00:00Z",
  },
];
const demoBotConfig: BotConfig = {
  mode: "challenge",
  threshold: 60,
  ttl_seconds: 900,
  updated_at: "2026-08-16T09:42:00Z",
};
const demoCrawlers: TrustedCrawler[] = [
  {
    id: 1,
    category: "trusted_crawler",
    weight: 10,
    trusted_user_agent: "Googlebot",
    trusted_domain: "googlebot.com",
    enabled: true,
  },
];
const demoRateConfig: RateLimitConfig = {
  enabled: true,
  action: "block",
  capacity: 1000,
  refill_per_second: 10,
  key_scope: "proxy_host_ip",
  updated_at: "2026-08-16T09:42:00Z",
};
const emptyWafConfig: WafConfig = { mode: "monitor-only", updated_at: "" };
const emptyBotConfig: BotConfig = {
  mode: "monitor",
  threshold: 0,
  ttl_seconds: 0,
  updated_at: "",
};
const emptyRateConfig: RateLimitConfig = {
  enabled: false,
  action: "monitor",
  capacity: 0,
  refill_per_second: 0,
  key_scope: "proxy_host_ip",
  updated_at: "",
};
const demoIpRules: IpSecurityRule[] = [
  {
    id: 1,
    cidr: "203.0.113.0/24",
    action: "block",
    score: 90,
    country_code: null,
    enabled: true,
    created_at: "2026-08-16T09:42:00Z",
    updated_at: "2026-08-16T09:42:00Z",
  },
];
const emptyIpRule = {
  cidr: "",
  action: "monitor" as IpSecurityAction,
  score: "0",
  country_code: "",
  enabled: true,
};

type RuleForm = {
  name: string;
  category: string;
  severity: string;
  action: WafAction;
  matcher: string;
};
const emptyRule: RuleForm = {
  name: "",
  category: "custom",
  severity: "medium",
  action: "inherit",
  matcher: '{"path":"/api"}',
};

export function Security() {
  const user = useAuthStore((state) => state.user);
  const { t } = useTranslation();
  const isAdmin = user?.role === "admin";
  const initialTab = new URLSearchParams(window.location.search).get("tab");
  const [activeTab, setActiveTab] = useState(
    initialTab === "bot"
      ? "bot"
      : initialTab === "rate"
        ? "rate"
        : initialTab === "ip"
          ? "ip"
          : "waf",
  );
  const [wafConfig, setWafConfig] = useState<WafConfig>(
    DEMO_MODE ? demoWafConfig : emptyWafConfig,
  );
  const [rules, setRules] = useState<WafRule[]>(DEMO_MODE ? demoRules : []);
  const [botConfig, setBotConfig] = useState<BotConfig>(
    DEMO_MODE ? demoBotConfig : emptyBotConfig,
  );
  const [crawlers, setCrawlers] = useState<TrustedCrawler[]>(
    DEMO_MODE ? demoCrawlers : [],
  );
  const [rateConfig, setRateConfig] = useState<RateLimitConfig>(
    DEMO_MODE ? demoRateConfig : emptyRateConfig,
  );
  const [ipRules, setIpRules] = useState<IpSecurityRule[]>(
    DEMO_MODE ? demoIpRules : [],
  );
  const [feedback, setFeedback] = useState<WafFeedback[]>([]);
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [toml, setToml] = useState("");
  const [ruleOpen, setRuleOpen] = useState(false);
  const [confirmRule, setConfirmRule] = useState<WafRule | null>(null);
  const [ruleForm, setRuleForm] = useState<RuleForm>(emptyRule);
  const [ipRuleOpen, setIpRuleOpen] = useState(false);
  const [ipRuleForm, setIpRuleForm] = useState(emptyIpRule);
  const [feedbackForm, setFeedbackForm] = useState({
    request_id: "",
    rule_id: "",
    note: "",
  });

  const refresh = async () => {
    if (DEMO_MODE) return;
    setLoading(true);
    setError("");
    const results = await Promise.allSettled([
      api.wafConfig(),
      api.wafRules(),
      api.botConfig(),
      api.trustedCrawlers(),
      api.rateLimitConfig(),
      api.ipSecurityRules(),
      api.wafFeedback(),
    ]);
    const [waf, wafRules, bot, crawlerRows, rate, ip, feedbackRows] = results;
    if (waf.status === "fulfilled") setWafConfig(waf.value);
    if (wafRules.status === "fulfilled") setRules(wafRules.value);
    if (bot.status === "fulfilled") setBotConfig(bot.value);
    if (crawlerRows.status === "fulfilled") setCrawlers(crawlerRows.value);
    if (rate.status === "fulfilled") setRateConfig(rate.value);
    if (ip.status === "fulfilled") setIpRules(ip.value);
    if (feedbackRows.status === "fulfilled") setFeedback(feedbackRows.value);
    const rejected = results.find((result) => result.status === "rejected");
    if (rejected?.status === "rejected")
      setError(sanitizeError(rejected.reason));
    setLoading(false);
  };

  useEffect(() => {
    void refresh();
  }, []);
  useRealtimeRefresh(
    ["waf.changed", "bot.changed", "rate_limit.changed", "security.changed"],
    refresh,
  );

  const updateWafMode = async () => {
    const mode: WafMode = wafConfig.mode === "block" ? "monitor-only" : "block";
    setBusy(true);
    try {
      if (DEMO_MODE) setWafConfig({ ...wafConfig, mode });
      else setWafConfig(await api.updateWafConfig({ mode }));
      toast.success(
        t("security.wafModeChanged", {
          mode:
            mode === "block"
              ? t("security.blocking")
              : t("security.monitorOnly"),
        }),
      );
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const saveRule = async (event: FormEvent) => {
    event.preventDefault();
    let matcher: unknown;
    try {
      matcher = JSON.parse(ruleForm.matcher);
    } catch {
      setError(t("security.matcherJsonError"));
      return;
    }
    setBusy(true);
    try {
      if (DEMO_MODE)
        setRules((current) => [
          ...current,
          {
            id: Date.now(),
            name: ruleForm.name,
            source: "custom",
            category: ruleForm.category,
            severity: ruleForm.severity,
            enabled: true,
            action: ruleForm.action,
            matcher_json: ruleForm.matcher,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ]);
      else
        await api.createWafRule({
          name: ruleForm.name.trim(),
          category: ruleForm.category.trim(),
          severity: ruleForm.severity.trim(),
          action: ruleForm.action,
          matcher,
        });
      if (!DEMO_MODE) await refresh();
      setRuleOpen(false);
      setRuleForm(emptyRule);
      toast.success(t("security.wafRuleCreated"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const toggleRule = async (rule: WafRule) => {
    if (rule.source !== "custom") {
      toast.info(t("security.builtinRuleNotice"));
      return;
    }
    setBusy(true);
    try {
      if (DEMO_MODE)
        setRules((current) =>
          current.map((item) =>
            item.id === rule.id ? { ...item, enabled: !item.enabled } : item,
          ),
        );
      else {
        await api.updateWafRule(rule.id, { enabled: !rule.enabled });
        await refresh();
      }
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const deleteRule = (rule: WafRule) => {
    setConfirmRule(rule);
  };

  const confirmDeleteRule = async () => {
    if (!confirmRule) return;
    const rule = confirmRule;
    setConfirmRule(null);
    setBusy(true);
    try {
      if (DEMO_MODE)
        setRules((current) => current.filter((item) => item.id !== rule.id));
      else {
        await api.deleteWafRule(rule.id);
        await refresh();
      }
      toast.success(t("security.wafRuleDeleted"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const importWaf = async () => {
    setBusy(true);
    try {
      if (DEMO_MODE) toast.success(t("security.demoWafImported"));
      else {
        await api.importWafRules(toml);
        await refresh();
      }
      setToml("");
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };
  const exportWaf = async () => {
    try {
      const value = DEMO_MODE
        ? "version = 1\nmode = 'block'\n"
        : await api.exportWafRules();
      setToml(value);
      toast.success(t("security.wafTomlLoaded"));
    } catch (exception) {
      setError(sanitizeError(exception));
    }
  };

  const saveBot = async (
    next: Pick<BotConfig, "mode" | "threshold" | "ttl_seconds">,
  ) => {
    setBusy(true);
    try {
      if (DEMO_MODE) setBotConfig({ ...botConfig, ...next });
      else setBotConfig(await api.updateBotConfig(next));
      toast.success(t("security.botPolicySaved"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };
  const toggleCrawler = async (crawler: TrustedCrawler) => {
    setBusy(true);
    try {
      if (DEMO_MODE)
        setCrawlers((current) =>
          current.map((item) =>
            item.id === crawler.id ? { ...item, enabled: !item.enabled } : item,
          ),
        );
      else {
        await api.updateTrustedCrawler(crawler.id, {
          user_agent: crawler.trusted_user_agent ?? "",
          domain: crawler.trusted_domain ?? "",
          enabled: !crawler.enabled,
        });
        await refresh();
      }
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };
  const addCrawler = async (userAgent: string, domain: string) => {
    setBusy(true);
    try {
      if (DEMO_MODE)
        setCrawlers((current) => [
          ...current,
          {
            id: Date.now(),
            category: "trusted_crawler",
            weight: 10,
            trusted_user_agent: userAgent,
            trusted_domain: domain,
            enabled: true,
          },
        ]);
      else {
        await api.createTrustedCrawler({
          user_agent: userAgent,
          domain,
          enabled: true,
        });
        await refresh();
      }
      toast.success(t("security.trustedCrawlerAdded"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };
  const deleteCrawler = async (crawler: TrustedCrawler) => {
    setBusy(true);
    try {
      if (DEMO_MODE)
        setCrawlers((current) =>
          current.filter((item) => item.id !== crawler.id),
        );
      else {
        await api.deleteTrustedCrawler(crawler.id);
        await refresh();
      }
      toast.success(t("security.trustedCrawlerRemoved"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };
  const importBot = async () => {
    setBusy(true);
    try {
      if (DEMO_MODE) toast.success(t("security.demoBotImported"));
      else {
        await api.importBotConfig(toml);
        await refresh();
      }
      setToml("");
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };
  const exportBot = async () => {
    try {
      const value = DEMO_MODE
        ? "version = 1\nmode = 'challenge'\nthreshold = 60\nttl_seconds = 900\n"
        : await api.exportBotConfig();
      setToml(value);
      toast.success(t("security.botTomlLoaded"));
    } catch (exception) {
      setError(sanitizeError(exception));
    }
  };

  const saveRate = async (
    next: Pick<
      RateLimitConfig,
      "enabled" | "action" | "capacity" | "refill_per_second" | "key_scope"
    >,
  ) => {
    setBusy(true);
    try {
      if (DEMO_MODE) setRateConfig({ ...rateConfig, ...next });
      else setRateConfig(await api.updateRateLimitConfig(next));
      toast.success(t("security.ratePolicySaved"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const saveIpRule = async (event: FormEvent) => {
    event.preventDefault();
    const score = Number(ipRuleForm.score);
    if (
      !ipRuleForm.cidr.trim() ||
      !Number.isInteger(score) ||
      score < -100000 ||
      score > 100000
    ) {
      setError(t("security.ipRuleValidation"));
      return;
    }
    setBusy(true);
    try {
      if (DEMO_MODE)
        setIpRules((current) => [
          ...current,
          {
            id: Date.now(),
            cidr: ipRuleForm.cidr.trim(),
            action: ipRuleForm.action,
            score,
            country_code: ipRuleForm.country_code.trim() || null,
            enabled: ipRuleForm.enabled,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ]);
      else
        await api.createIpSecurityRule({
          cidr: ipRuleForm.cidr.trim(),
          action: ipRuleForm.action,
          score,
          country_code: ipRuleForm.country_code.trim() || null,
          enabled: ipRuleForm.enabled,
        });
      if (!DEMO_MODE) await refresh();
      setIpRuleForm(emptyIpRule);
      setIpRuleOpen(false);
      toast.success(t("security.ipRuleCreated"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const toggleIpRule = async (rule: IpSecurityRule) => {
    setBusy(true);
    try {
      if (DEMO_MODE)
        setIpRules((current) =>
          current.map((item) =>
            item.id === rule.id ? { ...item, enabled: !item.enabled } : item,
          ),
        );
      else {
        await api.updateIpSecurityRule(rule.id, { enabled: !rule.enabled });
        await refresh();
      }
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const deleteIpRule = async (rule: IpSecurityRule) => {
    setBusy(true);
    try {
      if (DEMO_MODE)
        setIpRules((current) => current.filter((item) => item.id !== rule.id));
      else {
        await api.deleteIpSecurityRule(rule.id);
        await refresh();
      }
      toast.success(t("security.ipRuleDeleted"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const submitFeedback = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      if (!DEMO_MODE)
        await api.createWafFeedback({
          request_id: feedbackForm.request_id.trim() || undefined,
          rule_id: feedbackForm.rule_id
            ? Number(feedbackForm.rule_id)
            : undefined,
          label: "false_positive",
          note: feedbackForm.note.trim(),
        });
      setFeedback((current) =>
        DEMO_MODE
          ? [
              {
                id: Date.now(),
                reporter_id: null,
                request_id: feedbackForm.request_id.trim() || null,
                rule_id: feedbackForm.rule_id
                  ? Number(feedbackForm.rule_id)
                  : null,
                label: "false_positive",
                note: feedbackForm.note.trim(),
                created_at: new Date().toISOString(),
              },
              ...current,
            ]
          : current,
      );
      if (!DEMO_MODE) await refresh();
      setFeedbackForm({ request_id: "", rule_id: "", note: "" });
      toast.success(t("security.feedbackRecorded"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Main>
      <PageHeader
        title={t("security.title")}
        description={t("security.pageDescription")}
        action={
          <>
            <Badge
              variant="outline"
              className="hidden gap-1.5 rounded-full sm:inline-flex"
            >
              <span
                className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : "bg-emerald-500"}`}
              />
              {DEMO_MODE ? t("security.demoData") : t("security.apiConnected")}
            </Badge>
            <Button
              variant="outline"
              size="icon"
              aria-label={t("security.refresh")}
              onClick={() => void refresh()}
              disabled={loading}
            >
              <RefreshCw className={loading ? "animate-spin" : ""} />
            </Button>
          </>
        }
      />
      {error && (
        <div
          role="alert"
          className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
        >
          {error}
        </div>
      )}
      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <SecuritySummary
          icon={ShieldCheck}
          label={t("security.wafEngine")}
          status={wafConfig.mode === "block" ? "healthy" : "warning"}
          value={
            wafConfig.mode === "block"
              ? t("security.enforcing")
              : t("security.monitorOnly")
          }
          detail={t("security.rulesConfigured", { count: rules.length })}
        />
        <SecuritySummary
          icon={Bot}
          label={t("security.botProtection")}
          status={botConfig.mode === "monitor" ? "warning" : "healthy"}
          value={
            botConfig.mode === "monitor"
              ? t("security.monitoring")
              : botConfig.mode === "challenge"
                ? t("security.challenging")
                : t("security.blocking")
          }
          detail={t("security.trustedCrawlersCount", {
            count: crawlers.length,
          })}
        />
        <SecuritySummary
          icon={Activity}
          label={t("security.rateLimiting")}
          status={rateConfig.enabled ? "healthy" : "warning"}
          value={
            rateConfig.enabled ? t("security.enabled") : t("security.paused")
          }
          detail={t("security.burstCapacityValue", {
            value: rateConfig.capacity.toLocaleString(),
          })}
        />
      </div>
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>{t("security.coverageTitle")}</CardTitle>
          <CardDescription>{t("security.coverageDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {securityCoverage.map((item) => (
            <SecurityCapability
              key={item.key}
              title={t(`security.${item.key}Title`)}
              detail={t(`security.${item.key}Detail`)}
              status={
                item.status === "available"
                  ? "healthy"
                  : item.status === "partial"
                    ? "info"
                    : "warning"
              }
              label={t(`security.${item.status}`)}
            />
          ))}
        </CardContent>
      </Card>
      <Tabs
        value={activeTab}
        onValueChange={setActiveTab}
        className="space-y-6"
      >
        <TabsList>
          <TabsTrigger value="waf">{t("security.wafRulesTab")}</TabsTrigger>
          <TabsTrigger value="bot">{t("security.botProtection")}</TabsTrigger>
          <TabsTrigger value="rate">{t("security.rateLimiting")}</TabsTrigger>
          <TabsTrigger value="ip">{t("security.ipGeoTab")}</TabsTrigger>
        </TabsList>
        <TabsContent value="waf">
          <WafPanel
            config={wafConfig}
            rules={rules}
            canWrite={isAdmin}
            busy={busy}
            onToggle={() => void updateWafMode()}
            onAdd={() => setRuleOpen(true)}
            onToggleRule={(rule) => void toggleRule(rule)}
            onDelete={(rule) => void deleteRule(rule)}
            toml={toml}
            setToml={setToml}
            onImport={() => void importWaf()}
            onExport={() => void exportWaf()}
          />
        </TabsContent>
        <TabsContent value="bot">
          <BotPanel
            config={botConfig}
            crawlers={crawlers}
            canWrite={isAdmin}
            busy={busy}
            onSave={(next) => void saveBot(next)}
            onToggleCrawler={(crawler) => void toggleCrawler(crawler)}
            onDeleteCrawler={(crawler) => void deleteCrawler(crawler)}
            onAddCrawler={(userAgent, domain) =>
              void addCrawler(userAgent, domain)
            }
            toml={toml}
            setToml={setToml}
            onImport={() => void importBot()}
            onExport={() => void exportBot()}
          />
        </TabsContent>
        <TabsContent value="rate">
          <RatePanel
            config={rateConfig}
            canWrite={isAdmin}
            busy={busy}
            onSave={(next) => void saveRate(next)}
          />
        </TabsContent>
        <TabsContent value="ip">
          <IpSecurityPanel
            rules={ipRules}
            feedback={feedback}
            canWrite={isAdmin}
            busy={busy}
            onAdd={() => setIpRuleOpen(true)}
            onToggle={(rule) => void toggleIpRule(rule)}
            onDelete={(rule) => void deleteIpRule(rule)}
            feedbackForm={feedbackForm}
            setFeedbackForm={setFeedbackForm}
            onSubmitFeedback={(event) => void submitFeedback(event)}
          />
        </TabsContent>
      </Tabs>
      <Dialog open={ruleOpen} onOpenChange={setRuleOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("security.customWafRule")}</DialogTitle>
            <DialogDescription>
              {t("security.customWafDescription")}
            </DialogDescription>
          </DialogHeader>
          <form
            id="rule-form"
            className="space-y-4"
            onSubmit={(event) => void saveRule(event)}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                label={t("security.ruleName")}
                value={ruleForm.name}
                onChange={(value) => setRuleForm({ ...ruleForm, name: value })}
                placeholder={t("security.ruleNamePlaceholder")}
              />
              <Field
                label={t("security.category")}
                value={ruleForm.category}
                onChange={(value) =>
                  setRuleForm({ ...ruleForm, category: value })
                }
                placeholder={t("security.categoryPlaceholder")}
              />
              <Field
                label={t("waf.severity")}
                value={ruleForm.severity}
                onChange={(value) =>
                  setRuleForm({ ...ruleForm, severity: value })
                }
                placeholder={t("security.severityPlaceholder")}
              />
              <div className="space-y-2">
                <Label htmlFor="rule-action">{t("security.action")}</Label>
                <select
                  id="rule-action"
                  value={ruleForm.action}
                  onChange={(event) =>
                    setRuleForm({
                      ...ruleForm,
                      action: event.target.value as WafAction,
                    })
                  }
                  className="h-9 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="inherit">{t("security.inherit")}</option>
                  <option value="allow">{t("security.allow")}</option>
                  <option value="log">{t("security.log")}</option>
                  <option value="block">{t("security.block")}</option>
                </select>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="rule-matcher">{t("security.matcherJson")}</Label>
              <textarea
                id="rule-matcher"
                value={ruleForm.matcher}
                onChange={(event) =>
                  setRuleForm({ ...ruleForm, matcher: event.target.value })
                }
                className="min-h-28 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs outline-none focus:ring-2 focus:ring-ring/50"
              />
            </div>
          </form>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRuleOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" form="rule-form" disabled={busy || !isAdmin}>
              <FilePlus2 />
              {t("security.addRule")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={confirmRule != null}
        onOpenChange={(open) => {
          if (!open && !busy) setConfirmRule(null);
        }}
        title={t("security.deleteWafRuleTitle")}
        description={
          confirmRule
            ? `The custom rule “${confirmRule.name}” will stop evaluating traffic immediately.`
            : t("security.deleteWafRuleDescription")
        }
        pending={busy}
        onConfirm={() => void confirmDeleteRule()}
      />
      <Dialog open={ipRuleOpen} onOpenChange={setIpRuleOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("security.addIpPolicy")}</DialogTitle>
            <DialogDescription>{t("security.ipDescription")}</DialogDescription>
          </DialogHeader>
          <form
            id="ip-rule-form"
            className="space-y-4"
            onSubmit={(event) => void saveIpRule(event)}
          >
            <Field
              label={t("security.cidr")}
              value={ipRuleForm.cidr}
              onChange={(value) =>
                setIpRuleForm({ ...ipRuleForm, cidr: value })
              }
              placeholder={t("security.cidrPlaceholder")}
            />
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="ip-action">{t("security.action")}</Label>
                <select
                  id="ip-action"
                  value={ipRuleForm.action}
                  onChange={(event) =>
                    setIpRuleForm({
                      ...ipRuleForm,
                      action: event.target.value as IpSecurityAction,
                    })
                  }
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="monitor">{t("security.monitor")}</option>
                  <option value="block">{t("security.block")}</option>
                  <option value="allow">{t("security.allow")}</option>
                </select>
              </div>
              <Field
                label={t("security.reputationScore")}
                type="number"
                value={ipRuleForm.score}
                onChange={(value) =>
                  setIpRuleForm({ ...ipRuleForm, score: value })
                }
              />
            </div>
            <Field
              label={t("security.countryCodeOptional")}
              value={ipRuleForm.country_code}
              onChange={(value) =>
                setIpRuleForm({ ...ipRuleForm, country_code: value })
              }
              placeholder={t("security.countryPlaceholder")}
            />
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={ipRuleForm.enabled}
                onChange={(event) =>
                  setIpRuleForm({
                    ...ipRuleForm,
                    enabled: event.target.checked,
                  })
                }
                className="size-4 accent-primary"
              />
              {t("security.enableImmediately")}
            </label>
          </form>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIpRuleOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" form="ip-rule-form" disabled={busy}>
              <Globe2 />
              {t("common.save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Main>
  );
}

const securityCoverage = [
  { key: "waf", status: "available" },
  { key: "virtualPatching", status: "available" },
  { key: "botChallenge", status: "partial" },
  { key: "ipGeo", status: "available" },
  { key: "authChallenge", status: "available" },
  { key: "falsePositiveLoop", status: "available" },
] as const;

function SecurityCapability({
  title,
  detail,
  status,
  label,
}: {
  title: string;
  detail: string;
  status: "healthy" | "warning" | "info";
  label: string;
}) {
  return (
    <div className="rounded-lg border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-medium">{title}</p>
        <StatusBadge status={status}>{label}</StatusBadge>
      </div>
      <p className="mt-2 text-xs leading-5 text-muted-foreground">{detail}</p>
    </div>
  );
}

function IpSecurityPanel({
  rules,
  feedback,
  canWrite,
  busy,
  onAdd,
  onToggle,
  onDelete,
  feedbackForm,
  setFeedbackForm,
  onSubmitFeedback,
}: {
  rules: IpSecurityRule[];
  feedback: WafFeedback[];
  canWrite: boolean;
  busy: boolean;
  onAdd: () => void;
  onToggle: (rule: IpSecurityRule) => void;
  onDelete: (rule: IpSecurityRule) => void;
  feedbackForm: { request_id: string; rule_id: string; note: string };
  setFeedbackForm: (value: {
    request_id: string;
    rule_id: string;
    note: string;
  }) => void;
  onSubmitFeedback: (event: FormEvent) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,1.3fr)_minmax(320px,1fr)]">
      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4">
          <div>
            <CardTitle>{t("security.ipTitle")}</CardTitle>
            <CardDescription>{t("security.ipDescription")}</CardDescription>
          </div>
          <Button onClick={onAdd} disabled={!canWrite}>
            <Plus />
            {t("security.addRule")}
          </Button>
        </CardHeader>
        <CardContent>
          {rules.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              {t("security.noIpRules")}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="pb-3 font-medium">CIDR</th>
                    <th className="pb-3 font-medium">{t("security.action")}</th>
                    <th className="pb-3 font-medium">{t("anomaly.score")}</th>
                    <th className="pb-3 font-medium">
                      {t("security.country")}
                    </th>
                    <th className="pb-3 text-right font-medium">
                      {t("security.controls")}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule) => (
                    <tr className="border-b last:border-0" key={rule.id}>
                      <td className="py-3 font-mono text-xs">{rule.cidr}</td>
                      <td className="py-3">
                        <Badge
                          variant={
                            rule.action === "block"
                              ? "destructive"
                              : "secondary"
                          }
                        >
                          {rule.action}
                        </Badge>
                      </td>
                      <td className="py-3 tabular-nums">{rule.score}</td>
                      <td className="py-3">{rule.country_code ?? "—"}</td>
                      <td className="py-3 text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label={t("security.toggleRule", {
                              value: rule.cidr,
                            })}
                            onClick={() => onToggle(rule)}
                            disabled={!canWrite || busy}
                          >
                            <Check
                              className={
                                rule.enabled
                                  ? "text-emerald-600"
                                  : "text-muted-foreground"
                              }
                            />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label={t("security.deleteRule", {
                              value: rule.cidr,
                            })}
                            onClick={() => onDelete(rule)}
                            disabled={!canWrite || busy}
                          >
                            <Trash2 />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>{t("security.falsePositiveFeedback")}</CardTitle>
          <CardDescription>
            {t("security.falsePositiveDescription")}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <form className="space-y-3" onSubmit={onSubmitFeedback}>
            <Field
              label={t("security.requestIdOptional")}
              value={feedbackForm.request_id}
              onChange={(value) =>
                setFeedbackForm({ ...feedbackForm, request_id: value })
              }
              placeholder="req_…"
            />
            <Field
              label={t("security.ruleIdOptional")}
              type="number"
              value={feedbackForm.rule_id}
              onChange={(value) =>
                setFeedbackForm({ ...feedbackForm, rule_id: value })
              }
              placeholder="42"
            />
            <div className="space-y-2">
              <Label htmlFor="feedback-note">{t("security.analystNote")}</Label>
              <textarea
                id="feedback-note"
                value={feedbackForm.note}
                onChange={(event) =>
                  setFeedbackForm({ ...feedbackForm, note: event.target.value })
                }
                className="min-h-20 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                maxLength={1024}
              />
            </div>
            <Button
              type="submit"
              disabled={!canWrite || busy}
              className="w-full"
            >
              <FilePlus2 />
              {t("security.recordFalsePositive")}
            </Button>
          </form>
          <div className="border-t pt-4">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              {t("security.recentLabels")}
            </p>
            {feedback.slice(0, 4).map((item) => (
              <div
                className="mt-3 rounded-md border px-3 py-2 text-xs"
                key={item.id}
              >
                <div className="flex justify-between gap-2">
                  <Badge variant="outline">{item.label}</Badge>
                  <span className="text-muted-foreground">
                    {item.rule_id == null
                      ? t("security.noRule")
                      : `${t("anomaly.rule")} ${item.rule_id}`}
                  </span>
                </div>
                <p className="mt-1 text-muted-foreground">
                  {item.note || t("security.noNote")}
                </p>
              </div>
            ))}
            {feedback.length === 0 && (
              <p className="mt-3 text-xs text-muted-foreground">
                {t("security.noFeedback")}
              </p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function WafPanel({
  config,
  rules,
  canWrite,
  busy,
  onToggle,
  onAdd,
  onToggleRule,
  onDelete,
  toml,
  setToml,
  onImport,
  onExport,
}: {
  config: WafConfig;
  rules: WafRule[];
  canWrite: boolean;
  busy: boolean;
  onToggle: () => void;
  onAdd: () => void;
  onToggleRule: (rule: WafRule) => void;
  onDelete: (rule: WafRule) => void;
  toml: string;
  setToml: (value: string) => void;
  onImport: () => void;
  onExport: () => void;
}) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle>{t("security.webFirewall")}</CardTitle>
          <CardDescription>
            {t("security.webFirewallDescription")}
          </CardDescription>
        </div>
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="outline" onClick={onAdd} disabled={!canWrite}>
            <Plus />
            {t("security.addRule")}
          </Button>
          <Button
            variant={config.mode === "block" ? "outline" : "secondary"}
            onClick={onToggle}
            disabled={!canWrite || busy}
            aria-pressed={config.mode === "block"}
          >
            <LockKeyhole />
            {config.mode === "block"
              ? t("security.switchToMonitor")
              : t("security.enableBlocking")}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-xs text-muted-foreground">
                <th className="pb-3 font-medium">{t("security.ruleFamily")}</th>
                <th className="pb-3 font-medium">{t("security.source")}</th>
                <th className="pb-3 font-medium">{t("waf.severity")}</th>
                <th className="pb-3 font-medium">{t("security.action")}</th>
                <th className="pb-3 font-medium">{t("security.state")}</th>
                <th className="pb-3 text-right font-medium">
                  {t("security.controls")}
                </th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id} className="border-b last:border-0">
                  <td className="py-4 font-medium">{rule.name}</td>
                  <td className="py-4 text-muted-foreground">{rule.source}</td>
                  <td className="py-4">
                    <Badge
                      variant={
                        rule.severity === "high" || rule.severity === "critical"
                          ? "destructive"
                          : "secondary"
                      }
                    >
                      {rule.severity}
                    </Badge>
                  </td>
                  <td className="py-4 font-mono text-xs">{rule.action}</td>
                  <td className="py-4">
                    <StatusBadge status={rule.enabled ? "healthy" : "warning"}>
                      {rule.enabled
                        ? t("security.enabled")
                        : t("proxyHosts.tlsDisabled")}
                    </StatusBadge>
                  </td>
                  <td className="py-4 text-right">
                    <div className="flex justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Toggle ${rule.name}`}
                        onClick={() => onToggleRule(rule)}
                        disabled={!canWrite || busy}
                      >
                        <Check
                          className={
                            rule.enabled
                              ? "text-emerald-600"
                              : "text-muted-foreground"
                          }
                        />
                      </Button>
                      {rule.source === "custom" && (
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Delete ${rule.name}`}
                          onClick={() => onDelete(rule)}
                          disabled={!canWrite || busy}
                        >
                          <Trash2 />
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {rules.length === 0 && (
          <p className="py-8 text-center text-sm text-muted-foreground">
            {t("security.noWafRules")}
          </p>
        )}
        <div className="mt-6 space-y-3 border-t pt-5">
          <div>
            <p className="text-sm font-medium">
              {t("security.rulePackExchange")}
            </p>
            <p className="text-xs text-muted-foreground">
              {t("security.rulePackDescription")}
            </p>
          </div>
          <textarea
            aria-label={t("waf.toml")}
            value={toml}
            onChange={(event) => setToml(event.target.value)}
            className="min-h-28 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs outline-none focus:ring-2 focus:ring-ring/50"
          />
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              onClick={onImport}
              disabled={!canWrite || busy || !toml.trim()}
            >
              <Upload />
              {t("waf.import")}
            </Button>
            <Button variant="outline" onClick={onExport} disabled={busy}>
              <Download />
              {t("security.loadExport")}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function BotPanel({
  config,
  crawlers,
  canWrite,
  busy,
  onSave,
  onToggleCrawler,
  onDeleteCrawler,
  onAddCrawler,
  toml,
  setToml,
  onImport,
  onExport,
}: {
  config: BotConfig;
  crawlers: TrustedCrawler[];
  canWrite: boolean;
  busy: boolean;
  onSave: (next: Pick<BotConfig, "mode" | "threshold" | "ttl_seconds">) => void;
  onToggleCrawler: (crawler: TrustedCrawler) => void;
  onDeleteCrawler: (crawler: TrustedCrawler) => void;
  onAddCrawler: (userAgent: string, domain: string) => void;
  toml: string;
  setToml: (value: string) => void;
  onImport: () => void;
  onExport: () => void;
}) {
  const { t } = useTranslation();
  const [mode, setMode] = useState<BotMode>(config.mode);
  const [threshold, setThreshold] = useState(String(config.threshold));
  const [ttl, setTtl] = useState(String(config.ttl_seconds));
  const [ua, setUa] = useState("");
  const [domain, setDomain] = useState("");
  useEffect(() => {
    setMode(config.mode);
    setThreshold(String(config.threshold));
    setTtl(String(config.ttl_seconds));
  }, [config]);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    onSave({ mode, threshold: Number(threshold), ttl_seconds: Number(ttl) });
  };
  const addCrawler = (event: FormEvent) => {
    event.preventDefault();
    if (!ua.trim() || !domain.trim()) return;
    onAddCrawler(ua.trim(), domain.trim());
    setUa("");
    setDomain("");
  };
  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <Card className="lg:col-span-3">
        <CardHeader>
          <CardTitle>{t("security.botPolicy")}</CardTitle>
          <CardDescription>
            {t("security.botPolicyDescription")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid gap-4 sm:grid-cols-3" onSubmit={submit}>
            <div className="space-y-2">
              <Label htmlFor="bot-mode">{t("security.mode")}</Label>
              <select
                id="bot-mode"
                value={mode}
                onChange={(event) => setMode(event.target.value as BotMode)}
                disabled={!canWrite || busy}
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="monitor">{t("security.monitor")}</option>
                <option value="challenge">{t("security.challenge")}</option>
                <option value="block">{t("security.block")}</option>
              </select>
            </div>
            <Field
              label={t("bot.riskThreshold")}
              type="number"
              value={threshold}
              onChange={setThreshold}
              disabled={!canWrite || busy}
            />
            <Field
              label={t("bot.challengeTtl")}
              type="number"
              value={ttl}
              onChange={setTtl}
              disabled={!canWrite || busy}
            />
            <Button
              type="submit"
              disabled={!canWrite || busy}
              className="sm:col-span-3"
            >
              <SlidersHorizontal />
              {t("bot.savePolicy")}
            </Button>
          </form>
          <div className="mt-6 border-t pt-5">
            <div className="mb-3">
              <p className="text-sm font-medium">{t("bot.trustedCrawlers")}</p>
              <p className="text-xs text-muted-foreground">
                {t("security.trustedCrawlerDescription")}
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="pb-3">{t("bot.userAgent")}</th>
                    <th className="pb-3">{t("acme.domains")}</th>
                    <th className="pb-3">{t("security.state")}</th>
                    <th className="pb-3 text-right">
                      {t("security.controls")}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {crawlers.map((crawler) => (
                    <tr className="border-b last:border-0" key={crawler.id}>
                      <td className="py-3 font-mono text-xs">
                        {crawler.trusted_user_agent ?? "—"}
                      </td>
                      <td className="py-3 text-muted-foreground">
                        {crawler.trusted_domain ?? "—"}
                      </td>
                      <td className="py-3">
                        <StatusBadge
                          status={crawler.enabled ? "healthy" : "warning"}
                        >
                          {crawler.enabled
                            ? t("security.enabled")
                            : t("proxyHosts.tlsDisabled")}
                        </StatusBadge>
                      </td>
                      <td className="py-3 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => onToggleCrawler(crawler)}
                          disabled={!canWrite || busy}
                        >
                          {crawler.enabled
                            ? t("security.disable")
                            : t("security.enable")}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Delete ${crawler.trusted_user_agent ?? "crawler"}`}
                          onClick={() => onDeleteCrawler(crawler)}
                          disabled={!canWrite || busy}
                        >
                          <Trash2 />
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <form
              className="mt-4 grid gap-3 sm:grid-cols-2"
              onSubmit={addCrawler}
            >
              <Field
                label={t("bot.userAgent")}
                value={ua}
                onChange={setUa}
                disabled={!canWrite || busy}
                placeholder="ExampleBot"
              />
              <Field
                label={t("bot.crawlerDomain")}
                value={domain}
                onChange={setDomain}
                disabled={!canWrite || busy}
                placeholder="example.com"
              />
              <Button
                type="submit"
                disabled={!canWrite || busy || !ua.trim() || !domain.trim()}
                className="sm:col-span-2"
              >
                <Plus />
                {t("bot.addCrawler")}
              </Button>
            </form>
          </div>
        </CardContent>
      </Card>
      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>{t("security.botExchange")}</CardTitle>
          <CardDescription>
            {t("security.botExchangeDescription")}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <textarea
            aria-label={t("bot.title")}
            value={toml}
            onChange={(event) => setToml(event.target.value)}
            className="min-h-44 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs outline-none focus:ring-2 focus:ring-ring/50"
          />
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              onClick={onImport}
              disabled={!canWrite || busy || !toml.trim()}
            >
              <Upload />
              {t("waf.import")}
            </Button>
            <Button variant="outline" onClick={onExport} disabled={busy}>
              <Download />
              {t("security.loadExport")}
            </Button>
          </div>
          <Button variant="secondary" className="w-full" asChild>
            <Link to="/bot-challenge" search={{}}>
              {t("security.openChallenge")}
            </Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function RatePanel({
  config,
  canWrite,
  busy,
  onSave,
}: {
  config: RateLimitConfig;
  canWrite: boolean;
  busy: boolean;
  onSave: (
    next: Pick<
      RateLimitConfig,
      "enabled" | "action" | "capacity" | "refill_per_second" | "key_scope"
    >,
  ) => void;
}) {
  const { t } = useTranslation();
  const [enabled, setEnabled] = useState(config.enabled);
  const [action, setAction] = useState<RateLimitAction>(config.action);
  const [capacity, setCapacity] = useState(String(config.capacity));
  const [refill, setRefill] = useState(String(config.refill_per_second));
  const [scope, setScope] = useState<RateLimitKeyScope>(config.key_scope);
  useEffect(() => {
    setEnabled(config.enabled);
    setAction(config.action);
    setCapacity(String(config.capacity));
    setRefill(String(config.refill_per_second));
    setScope(config.key_scope);
  }, [config]);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    onSave({
      enabled,
      action,
      capacity: Number(capacity),
      refill_per_second: Number(refill),
      key_scope: scope,
    });
  };
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader className="flex flex-row items-start justify-between">
          <div>
            <CardTitle>{t("security.adaptiveRate")}</CardTitle>
            <CardDescription>
              {t("security.adaptiveRateDescription")}
            </CardDescription>
          </div>
          <StatusBadge status={config.enabled ? "healthy" : "warning"}>
            {config.enabled ? t("security.enabled") : t("security.paused")}
          </StatusBadge>
        </CardHeader>
        <CardContent>
          <form className="grid gap-4 sm:grid-cols-2" onSubmit={submit}>
            <label className="flex min-h-9 items-center gap-3 text-sm font-medium sm:col-span-2">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(event) => setEnabled(event.target.checked)}
                disabled={!canWrite || busy}
                className="size-4 accent-primary"
              />
              {t("rateLimit.enable")}
            </label>
            <div className="space-y-2">
              <Label htmlFor="rate-action">{t("security.action")}</Label>
              <select
                id="rate-action"
                value={action}
                onChange={(event) =>
                  setAction(event.target.value as RateLimitAction)
                }
                disabled={!canWrite || busy}
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="monitor">{t("security.monitorOnly")}</option>
                <option value="block">{t("rateLimit.blockLimited")}</option>
              </select>
            </div>
            <Field
              label={t("rateLimit.burstCapacity")}
              type="number"
              value={capacity}
              onChange={setCapacity}
              disabled={!canWrite || busy}
            />
            <Field
              label={t("rateLimit.refill")}
              type="number"
              value={refill}
              onChange={setRefill}
              disabled={!canWrite || busy}
            />
            <div className="space-y-2">
              <Label htmlFor="rate-scope">{t("rateLimit.keyScope")}</Label>
              <select
                id="rate-scope"
                value={scope}
                onChange={(event) =>
                  setScope(event.target.value as RateLimitKeyScope)
                }
                disabled={!canWrite || busy}
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="proxy_host_ip">
                  {t("rateLimit.scopeValue")}
                </option>
                <option value="proxy_host_path_ip">
                  {t("security.endpointClientIp")}
                </option>
              </select>
            </div>
            {canWrite && (
              <Button type="submit" disabled={busy} className="sm:col-span-2">
                <SlidersHorizontal />
                {t("rateLimit.savePolicy")}
              </Button>
            )}
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>{t("security.currentPolicy")}</CardTitle>
          <CardDescription>
            {t("security.currentPolicyDescription")}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <PolicyRow
            label={t("security.mode")}
            value={
              config.action === "block"
                ? t("security.blocking")
                : t("security.monitorOnly")
            }
          />
          <PolicyRow
            label={t("rateLimit.burstCapacity")}
            value={config.capacity.toLocaleString()}
          />
          <PolicyRow
            label={t("security.refillRate")}
            value={`${config.refill_per_second}/second`}
          />
          <PolicyRow
            label={t("security.scope")}
            value={
              config.key_scope === "proxy_host_path_ip"
                ? t("security.endpointClientIp")
                : t("rateLimit.scopeValue")
            }
          />
          <Button variant="outline" className="mt-3 w-full" asChild>
            <Link to="/analytics">{t("security.reviewAnomalies")}</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  disabled = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <Input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        required
      />
    </div>
  );
}
function PolicyRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border bg-muted/30 p-4 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}
function SecuritySummary({
  icon: Icon,
  label,
  value,
  detail,
  status,
}: {
  icon: typeof ShieldCheck;
  label: string;
  value: string;
  detail: string;
  status: "healthy" | "warning";
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {label}
        </CardTitle>
        <Icon className="size-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-2">
          <span className="text-xl font-semibold">{value}</span>
          <StatusBadge status={status}>
            {status === "healthy" ? "Healthy" : "Review"}
          </StatusBadge>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
      </CardContent>
    </Card>
  );
}
