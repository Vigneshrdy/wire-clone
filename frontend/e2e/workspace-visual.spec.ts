import { expect, test } from "@playwright/test";

const cases = [
  { route: "/network", theme: "light", width: 1440, height: 900, name: "network-light-1440" },
  { route: "/network", theme: "dark", width: 1440, height: 900, name: "network-dark-1440" },
  { route: "/models", theme: "light", width: 1440, height: 900, name: "models-light-1440" },
  { route: "/system", theme: "dark", width: 1440, height: 900, name: "system-dark-1440" },
  { route: "/network", theme: "dark", width: 390, height: 844, name: "network-dark-mobile" },
] as const;

for (const item of cases) {
  test(`${item.name} visual inspection`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
    await page.setViewportSize({ width: item.width, height: item.height });
    await page.addInitScript((theme) => localStorage.setItem("theme", theme), item.theme);
    await page.goto(item.route, { waitUntil: "networkidle" });
    await expect(page.locator("main")).toBeVisible();
    expect(errors).toEqual([]);
    await page.screenshot({ path: `e2e/screenshots/${item.name}.png`, fullPage: true });
  });
}
