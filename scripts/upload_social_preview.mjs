#!/usr/bin/env node
/**
 * Upload assets/social-preview.png to GitHub repo Social preview settings.
 * Requires an authenticated Chrome profile (Default) with GitHub access.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { chromium } from "playwright";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repo = process.argv[2] || "Stijnman/defensive-mcp-audit";
const imagePath = path.resolve(__dirname, "../assets/social-preview.png");
const chromeDataDir = path.join(process.env.HOME, ".config", "google-chrome");
const [owner, name] = repo.split("/");
const settingsUrl = `https://github.com/${owner}/${name}/settings`;

async function main() {
  if (!fs.existsSync(imagePath)) throw new Error(`Missing image: ${imagePath}`);

  const context = await chromium.launchPersistentContext(chromeDataDir, {
    channel: "chrome",
    headless: false,
    args: ["--profile-directory=Default", "--disable-dev-shm-usage"],
  });
  const page = context.pages()[0] || (await context.newPage());

  await page.goto(settingsUrl, { waitUntil: "domcontentloaded", timeout: 60000 });
  if (page.url().includes("/login")) {
    throw new Error("GitHub login required in Chrome Default profile");
  }

  const socialHeading = page.locator("xpath=//h2[normalize-space()='Social preview']").first();
  const editButton = page.locator("#edit-social-preview-button");
  const fileInput = page.locator("input#repo-image-file-input");
  const uploadMenuItem = page.getByText(/upload an image/i).first();
  const imageIdInput = page.locator("input.js-repository-image-id");

  await socialHeading.waitFor({ state: "attached", timeout: 60000 });
  await socialHeading.scrollIntoViewIfNeeded().catch(() => {});

  if (await editButton.count()) {
    await editButton.first().click({ force: true }).catch(() => {});
  }

  await Promise.any([
    fileInput.first().waitFor({ state: "attached", timeout: 30000 }),
    uploadMenuItem.waitFor({ state: "visible", timeout: 30000 }),
  ]);

  if (await fileInput.count()) {
    await fileInput.first().setInputFiles(imagePath);
  } else {
    const [chooser] = await Promise.all([
      page.waitForEvent("filechooser"),
      uploadMenuItem.click({ force: true }),
    ]);
    await chooser.setFiles(imagePath);
  }

  await page.waitForFunction(() => {
    const input = document.querySelector("input.js-repository-image-id");
    return Boolean((input?.value || "").trim());
  }, { timeout: 20000 });

  const imageId = await imageIdInput.first().inputValue().catch(() => "");
  console.log(`Social preview uploaded for ${repo} (image id: ${imageId || "unknown"})`);
  await context.close();
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});