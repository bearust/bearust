// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { RetrainPanel } from "./retrain-panel";
import { api } from "@/api";

let root: Root;
afterEach(async () => {
  if (root) await act(async () => root.unmount());
  vi.restoreAllMocks();
  document.body.innerHTML = "";
});

it("lists recommendations, applies them, and reverts a demoted rule", async () => {
  vi.spyOn(api, "wafRetrain").mockResolvedValue({ mode: "recommend", min_reports: 5, false_positive_percent: 80, window_days: 30 });
  const recs = vi.spyOn(api, "wafRetrainRecommendations").mockResolvedValue([{ rule_id: 942100, false_positives: 6, true_positives: 1 }]);
  vi.spyOn(api, "wafRuleTunings").mockResolvedValue([{ rule_id: 941100, kind: "seclang", previous_action: null, false_positives: 9, true_positives: 0, source: "auto", created_at: "2026-10-24T00:00:00Z" }]);
  const run = vi.spyOn(api, "runWafRetrain").mockResolvedValue([{ rule_id: 942100, false_positives: 6, true_positives: 1 }]);
  const revert = vi.spyOn(api, "revertWafRuleTuning").mockResolvedValue(undefined);
  root = createRoot(document.body);
  await act(async () => root.render(<RetrainPanel canWrite />));
  expect(document.body.textContent).toContain("Rule 942100: 6 false / 1 true positives");
  const button = (label: string) => [...document.querySelectorAll("button")].find((b) => b.textContent?.includes(label))!;
  await act(async () => button("Apply recommendations now").click());
  expect(run).toHaveBeenCalled();
  expect(recs).toHaveBeenCalledTimes(2);
  await act(async () => button("Revert").click());
  expect(revert).toHaveBeenCalledWith(941100);
});
