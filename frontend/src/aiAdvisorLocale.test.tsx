import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
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
});
