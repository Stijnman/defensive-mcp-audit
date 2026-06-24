#!/usr/bin/env node
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { chromium } from "playwright";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repo = process.argv[2] || "Stijnman/defensive-mcp-audit";
const imagePath = path.resolve(__dirname, "../assets/social-preview.png");

const profiles = {
  brave: path.join(process.env.HOME, ".config", "BraveSoftware", "Brave-Browser"),
  chromium: path.join(process.env.HOME, ".config", "chromium"),
  chrome: path.join(process.env.HOME, ".config", "google-chrome"),
};

const browserName = process.env.SOCIAL_PREVIEW_BROWSER || "brave";
const userDataDir = profiles[browserName];
const [owner, name] = repo.split("/");
const settingsUrl = `https://github.com/${owner}/${name}/settings`;

async function uploadWithPage(page) {
  await page.goto(settingsUrl, { waitUntil: "domcontentloaded", timeout: 90000 });
  if (page.url().includes("/login")) {
    throw new Error(`Not logged into GitHub in ${browserName} profile`);
  }

  const socialHeading = page.locator("xpath=//h2[normalize-space()='Social preview']").first();
  const editButton = page.locator("#edit-social-preview-button");
  const fileInput = page.locator("input#repo-image-file-input");
  const uploadMenuItem = page.getByText(/upload an image/i).first();
  const imageIdInput = page.locator("input.js-repository-image-id");

  await socialHeading.waitFor({ state: "attached", timeout: 90000 });
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
  }, { timeout: 30000 });

  const imageId = await imageIdInput.first().inputValue().catch(() => "");
  return imageId;
}

async function main() {
  if (!fs.existsSync(imagePath)) throw new Error(`Missing image: ${imagePath}`);
  if (!fs.existsSync(userDataDir)) throw new Error(`Missing profile: ${userDataDir}`);

  let context;
  try {
    const launchOptions = {
      headless: false,
      args: ["--profile-directory=Default", "--disable-dev-shm-usage", "--no-first-run"],
    };
    if (browserName === "brave") {
      launchOptions.executablePath = "/opt/brave.com/brave/brave";
    } else {
      launchOptions.channel = browserName;
    }
    context = await chromium.launchPersistentContext(userDataDir, launchOptions);
    const page = context.pages()[0] || (await context.newPage());
    const imageId = await uploadWithPage(page);
    console.log(`OK: social preview uploaded for ${repo} (image id: ${imageId || "set"})`);
  } catch (error) {
    if (String(error).includes("already in use")) {
      throw new Error(
        `${browserName} profile is locked. Close all ${browserName} windows and retry.`,
      );
    }
    throw error;
  } finally {
    if (context) await context.close().catch(() => {});
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});