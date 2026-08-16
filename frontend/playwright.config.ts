import { defineConfig } from "@playwright/test";

const apiMode = process.env.E2E_API === "1";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  webServer: {
    command: `${apiMode ? "npm run dev:api" : "npm run dev:demo"} -- --host 127.0.0.1 --port 4173`,
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: "http://127.0.0.1:4173",
    browserName: "chromium",
  },
});
