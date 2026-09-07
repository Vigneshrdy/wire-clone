import { expect, test } from "@playwright/test";

const routes = [
  ["/overview", "Operational picture"],
  ["/alerts", "Alert investigation"],
  ["/incidents", "Incident queue"],
  ["/network", "Network relationships"],
  ["/detectors", "Detector mesh"],
  ["/models", "Model governance"],
  ["/learning", "Continuous learning"],
  ["/replay", "Lab control"],
  ["/benchmarks", "Measured performance"],
  ["/system", "System diagnostics"],
] as const;

for (const [route, heading] of routes) {
  test(`${route} loads without client errors`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
    const response = await page.goto(route, { waitUntil: "networkidle" });
    expect(response?.ok()).toBe(true);
    await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  });
}

test("mobile navigation exposes every workspace", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/overview", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(page.getByRole("complementary", { name: "Primary navigation" })).toBeVisible();
  await expect(page.getByRole("link", { name: "System" })).toBeVisible();
});
