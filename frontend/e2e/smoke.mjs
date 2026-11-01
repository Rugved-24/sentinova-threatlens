import { chromium } from "playwright-core";

const base = process.env.THREATLENS_BASE_URL || "http://127.0.0.1:8000";
const password = "ThreatLens#2026!";

async function launchBrowser() {
  const options = { headless: true, args: ["--no-sandbox", "--disable-gpu"] };
  if (process.env.CHROME_PATH) {
    return chromium.launch({ ...options, executablePath: process.env.CHROME_PATH });
  }
  for (const channel of ["chrome", "msedge"]) {
    try {
      return await chromium.launch({ ...options, channel });
    } catch {
      // Try the next installed browser channel.
    }
  }
  throw new Error("Chrome or Edge is required. Set CHROME_PATH to an installed browser executable.");
}

async function login(page, email) {
  await page.goto(`${base}/login`, { waitUntil: "domcontentloaded" });
  await page.fill("#email", email);
  await page.fill("#password", password);
  await page.click("button[type=submit]");
  await page.waitForURL((url) => url.pathname === "/", { timeout: 15000 });
  await page.getByText("Risk posture overview", { exact: true }).first().waitFor({ timeout: 15000 });
}

function trackProblems(page, problems, prefix = "") {
  page.on("console", (message) => {
    if (message.type() === "error" && !message.text().includes("401 (Unauthorized)")) {
      problems.push(`${prefix}console: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => problems.push(`${prefix}pageerror: ${error.message}`));
  page.on("requestfailed", (request) => {
    if (!request.url().includes("favicon")) {
      problems.push(`${prefix}requestfailed: ${request.url()} ${request.failure()?.errorText || ""}`);
    }
  });
  page.on("response", (response) => {
    const url = response.url();
    if (response.status() >= 400 && !url.includes("/auth/refresh") && !url.includes("favicon")) {
      problems.push(`${prefix}http ${response.status()}: ${url}`);
    }
  });
}

const browser = await launchBrowser();
const problems = [];
const visited = [];

try {
  const adminContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await adminContext.newPage();
  trackProblems(page, problems);
  await login(page, "admin@threatlens.io");

  const routes = [
    ["Executive overview", "/", "Risk posture overview"],
    ["Analyst workspace", "/analyst", "Analyst workspace"],
    ["Incidents", "/incidents", "Response cases"],
    ["Threat hunting", "/hunting", "Hunt the corpus"],
    ["Reports", "/reports", "Reports"],
    ["Feeds & sources", "/feeds", "Feeds & sources"],
    ["Audit trail", "/audit", "Audit trail"],
    ["Users & roles", "/users", "Users & roles"],
    ["Settings", "/settings", "Settings"],
  ];

  for (const [label, path, title] of routes) {
    if (path !== "/") {
      await page.getByRole("link", { name: label, exact: true }).click();
      await page.waitForURL((url) => url.pathname === path, { timeout: 10000 });
    }
    await page.getByText(title, { exact: true }).first().waitFor({ timeout: 15000 });
    visited.push(path);
  }

  await page.keyboard.press("Control+k");
  await page.getByPlaceholder(/Search IPs/i).waitFor({ timeout: 5000 });
  await page.keyboard.type("hunt");
  await page.waitForTimeout(600);
  await page.keyboard.press("Escape");
  await adminContext.close();

  const execContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const execPage = await execContext.newPage();
  trackProblems(execPage, problems, "exec ");
  await login(execPage, "exec@threatlens.io");
  await execPage.getByText("No indicators in your clearance", { exact: true }).waitFor({ timeout: 15000 });
  const execBody = await execPage.locator("body").innerText();
  if (!execBody.includes("Executive accounts receive aggregate reporting without raw indicator values.")) {
    problems.push("executive dashboard did not render the aggregate-only empty state");
  }
  if (/203\.0\.113\.|198\.51\.100\.|192\.0\.2\./.test(execBody)) {
    problems.push("executive dashboard exposed a raw documentation-range IOC");
  }
  await execContext.close();
} finally {
  await browser.close();
}

console.log(JSON.stringify({ visited, executiveAggregateOnly: true, problems }, null, 2));
if (problems.length) process.exitCode = 1;
