import { createApiClient } from "./api.js";
import { createController } from "./controller.js";

const controller = createController(chrome, createApiClient());
chrome.runtime.onInstalled.addListener(() => { void controller.install(); });
chrome.contextMenus.onClicked.addListener(info => { void controller.contextCheck(info).catch(() => console.error("Unable to present NurtureShield check.")); });
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  controller.message(message, sender).then(sendResponse).catch(() => sendResponse({ error: { code: "service", message: "NurtureShield could not complete this request." } }));
  return true;
});
