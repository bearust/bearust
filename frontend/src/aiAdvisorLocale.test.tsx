import { describe, expect, it } from "vitest";
import en from "./locales/en.json";
import id from "./locales/id.json";
import ja from "./locales/ja.json";

const flatten = (value: object, prefix = ""): string[] => Object.entries(value).flatMap(([key, child]) => {
  const path = prefix ? `${prefix}.${key}` : key;
  return typeof child === "string" ? [path] : flatten(child, path);
});

describe("AI advisor locale catalogs", () => {
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
});
