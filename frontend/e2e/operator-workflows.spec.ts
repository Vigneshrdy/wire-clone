import { expect, test } from "@playwright/test";

test("operator access is session scoped and gates replay", async ({ page }) => {
  await page.goto("/system", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "Unlock operator mode" }).click();
  await expect(page.getByRole("dialog", { name: "Operator access" })).toBeVisible();
  await page.getByLabel("Management token").fill("test-session-token");
  await page.getByRole("button", { name: "Unlock session" }).click();
  await expect(page.getByText("Operator mode: Unlocked")).toBeVisible();

  await page.goto("/replay", { waitUntil: "networkidle" });
  await expect(page.getByRole("button", { name: "Review and start" })).toBeEnabled();
  await page.getByRole("button", { name: "Review and start" }).click();
  await expect(page.getByRole("dialog", { name: "Start passive replay" })).toBeVisible();
  await expect(page.getByText("3,000", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();

  await page.goto("/system", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "Lock session" }).click();
  await expect(page.getByText("Operator mode: Locked")).toBeVisible();
});

test("command menu supports keyboard navigation", async ({ page }) => {
  await page.goto("/overview", { waitUntil: "networkidle" });
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("dialog", { name: "Command menu" })).toBeVisible();
  await page.getByPlaceholder("Type a command or route").fill("System");
  await page.getByText("Go to System", { exact: true }).click();
  await expect(page).toHaveURL(/\/system$/);
});
