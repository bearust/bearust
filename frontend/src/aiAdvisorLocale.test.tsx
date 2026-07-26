// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { api, type AdvisorInsight } from "./api";
import { AiAdvisorSection } from "./aiAdvisor";
import { i18n, initI18n } from "./i18n";
import en from "./locales/en.json";
import id from "./locales/id.json";
import ja from "./locales/ja.json";

const flatten = (value: object, prefix = ""): string[] => Object.entries(value).flatMap(([key, child]) => {
  const path = prefix ? `${prefix}.${key}` : key;
  return typeof child === "string" ? [path] : flatten(child, path);
});

describe("AI advisor locale catalogs", () => {
  beforeAll(async () => { (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true; await initI18n("en"); });
  afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ""; });
  it("keep all locale keys in parity", () => {
    const source = flatten(en).sort();
    expect(flatten(id).sort()).toEqual(source);
    expect(flatten(ja).sort()).toEqual(source);
  });

  it.each([
    "advisor.title", "advisor.redactionNotice", "advisor.approve", "advisor.reject",
    "advisor.errors.advisor_busy", "advisor.errors.advisor_stale_draft", "advisor.errors.advisor_expired",
    "advisor.accessibility.refresh", "advisor.accessibility.result",
  ])("catalogues %s", (key) => expect(flatten(en)).toContain(key));

  it.each([["en", en], ["id", id], ["ja", ja]] as const)("renders advisor states for %s", (_locale, catalog) => {
    const advisor = catalog.advisor;
    const html = renderToStaticMarkup(createElement("section", null,
      createElement("h2", null, advisor.title),
      createElement("p", null, advisor.redactionNotice),
      createElement("span", null, advisor.status.queued),
      createElement("span", null, advisor.errors.advisor_busy),
      createElement("button", { "aria-label": advisor.accessibility.refresh }, advisor.refresh),
    ));
    expect(html).toContain(advisor.title);
    expect(html).toContain(advisor.redactionNotice);
    expect(html).toContain(advisor.status.queued);
    expect(html).toContain(advisor.errors.advisor_busy);
    expect(html).toContain(advisor.accessibility.refresh);
  });

  it.each(["en", "id", "ja"] as const)("renders actual advisor UI in %s", async (locale) => {
    await i18n.changeLanguage(locale);
    const insight: AdvisorInsight = { job_id: "locale-job", workflow: "incident_explanation", status: "completed", redacted_input: {}, redacted_result: { workflow: "incident_explanation", summary: "Localized result", severity: "warning", signals: [], reason_ids: [], score: 50 }, error_code: null, provider_model: "model", config_version: "v1", config_hash: "hash", created_at: "2026-01-01", updated_at: "2026-01-01", expires_at: "2099-01-01", draft_decision: null, draft_decided_at: null };
    vi.spyOn(api, "aiAdvisorStatus").mockResolvedValue({ enabled: true });
    vi.spyOn(api, "listAiInsights").mockResolvedValue({ page: 1, page_size: 20, total: 1, items: [insight] });
    const element = document.createElement("div"); document.body.appendChild(element); const root = createRoot(element);
    await act(async () => { root.render(<AiAdvisorSection user={{ id: 1, email: "admin@example.com", role: "admin", disabled: false }} />); });
    expect(element.textContent).toContain("Localized result");
    expect(element.textContent).toContain(i18n.t("advisor.status.completed"));
    root.unmount();
  });

  it("renders localized stale and expired errors from actual advisor actions", async () => {
    await i18n.changeLanguage("en");
    const draft: AdvisorInsight = { job_id: "draft-job", workflow: "configuration_draft", status: "completed", redacted_input: {}, redacted_result: { workflow: "configuration_draft", summary: "Draft", action: "set_waf_mode", mode: "monitor-only", expected_config_hash: "a".repeat(64) }, error_code: null, provider_model: "model", config_version: "v1", config_hash: "hash", created_at: "2026-01-01", updated_at: "2026-01-01", expires_at: "2099-01-01", draft_decision: null, draft_decided_at: null };
    vi.spyOn(api, "aiAdvisorStatus").mockResolvedValue({ enabled: true }); vi.spyOn(api, "listAiInsights").mockResolvedValue({ page: 1, page_size: 20, total: 1, items: [draft] }); vi.spyOn(api, "approveAiDraft").mockRejectedValue(Object.assign(new Error("provider detail"), { code: "advisor_stale_draft" }));
    const element = document.createElement("div"); document.body.appendChild(element); const root = createRoot(element); await act(async () => { root.render(<AiAdvisorSection user={{ id: 1, email: "admin@example.com", role: "admin", disabled: false }} />); });
    const button = [...element.querySelectorAll("button")].find((candidate) => candidate.textContent === "Approve draft"); await act(async () => { button?.dispatchEvent(new MouseEvent("click", { bubbles: true })); });
    expect(element.textContent).toContain(i18n.t("advisor.errors.advisor_stale_draft")); expect(element.textContent).not.toContain("provider detail"); expect(element.textContent).not.toContain("Approve draft"); root.unmount();
  });
});
