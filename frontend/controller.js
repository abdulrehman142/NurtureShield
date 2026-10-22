import { validateUrl } from "./api.js";

export const MENU_ID = "nurtureshield-check-link";
const PREFIX = "shield-job:";
const MAX_AGE = 10 * 60 * 1000;

export function createController(browser, analyze, { now = Date.now, makeId = () => crypto.randomUUID() } = {}) {
  const safeError = error => ({ code: error.code || "service", message: error.code ? error.message : "The link could not be analyzed. Please try again." });
  async function install() {
    await browser.contextMenus.removeAll();
    browser.contextMenus.create({ id: MENU_ID, title: "Check link with NurtureShield", contexts: ["link"], targetUrlPatterns: ["http://*/*", "https://*/*"] });
  }
  async function contextCheck(info) {
    if (info.menuItemId !== MENU_ID || typeof info.linkUrl !== "string") return;
    const id = makeId();
    const key = PREFIX + id;
    const all = await browser.storage.session.get(null);
    const jobs = Object.entries(all).filter(([key]) => key.startsWith(PREFIX)).sort((a, b) => b[1].createdAt - a[1].createdAt);
    await browser.storage.session.remove(jobs.filter(([, job], index) => now() - job.createdAt > MAX_AGE || index >= 19).map(([key]) => key));
    const job = { id, createdAt: now(), url: info.linkUrl.slice(0, 8192), phase: "loading" };
    await browser.storage.session.set({ [key]: job });
    // Only our own extension UI is opened, never info.linkUrl or info.pageUrl.
    await browser.tabs.create({ url: browser.runtime.getURL(`popup.html?job=${encodeURIComponent(id)}`) });
    try {
      const result = await analyze(validateUrl(info.linkUrl));
      await browser.storage.session.set({ [key]: { ...job, phase: "done", result } });
    } catch (error) {
      await browser.storage.session.set({ [key]: { ...job, phase: "error", error: safeError(error) } });
    }
  }
  async function message(message, sender) {
    // No content scripts or externally_connectable interface. Accept only our popup document.
    const page = browser.runtime.getURL("popup.html");
    if (sender.id !== browser.runtime.id || !sender.url || sender.url.split("?")[0] !== page) return { error: { code: "forbidden", message: "Untrusted sender." } };
    if (message?.type === "analyze") {
      try { return { result: await analyze(message.url) }; }
      catch (error) { return { error: safeError(error) }; }
    }
    if (message?.type === "job" && typeof message.id === "string" && /^[a-zA-Z0-9-]{1,80}$/.test(message.id)) {
      const key = PREFIX + message.id;
      const job = (await browser.storage.session.get(key))[key];
      if (!job || now() - job.createdAt > MAX_AGE) {
        await browser.storage.session.remove(key);
        return { error: { code: "expired", message: "This check has expired. Paste the link to check it again." } };
      }
      return { job };
    }
    return { error: { code: "request", message: "Unknown request." } };
  }
  return { install, contextCheck, message };
}
