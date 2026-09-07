import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"] as const) {
  for (const viewport of [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
    test(`overview ${theme} ${viewport.width}`, async ({ page }) => {
      const errors: string[] = [];
      page.on("console", (message) => { if (message.type() === "error" && !message.text().includes("/_next/hmr")) errors.push(message.text()); });
      await page.addInitScript((value) => localStorage.setItem("theme", value), theme);
      await page.setViewportSize(viewport);
      await page.goto("/overview");
      await expect(page.getByRole("heading", { name: "Operational picture" })).toBeVisible();
      await page.waitForTimeout(1800);
      await page.screenshot({ path: `e2e/screenshots/overview-${theme}-${viewport.width}.png`, fullPage: true });
      expect(errors).toEqual([]);
    });
  }
}
