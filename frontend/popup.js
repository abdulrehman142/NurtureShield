import { API_ORIGIN } from "./config.js";
import { validateUrl, validateAssessment } from "./api.js";
import { displayRisk, displayError } from "./presentation.js";

const $ = id => document.getElementById(id);
let jobId = new URLSearchParams(location.search).get("job");
let revision = 0;
let pendingTimer;
if (jobId) document.body.classList.add("result-page");

function busy(value) {
  $("check").disabled = value;
  $("current-tab").disabled = value;
  $("url").disabled = value;
  $("checker").setAttribute("aria-busy", String(value));
  $("status").textContent = value ? "Checking link…" : "";
  $("check-label").textContent = value ? "Checking link…" : "Check Link";
}
function inputView() {
  $("input-view").hidden = false; $("result").hidden = true; $("auth-state").hidden = true;
}
function clearResult() { inputView(); $("error").hidden = true; $("url").removeAttribute("aria-invalid"); }
function showError(error) {
  busy(false); inputView();
  if (error?.code === "auth") {
    $("input-view").hidden = true; $("error").hidden = true;
    $("auth-state").hidden = false; $("auth-title").focus();
    return;
  }
  $("error").textContent = displayError(error);
  $("error").hidden = false;
  if (error?.code === "validation") $("url").setAttribute("aria-invalid", "true");
}
function showResult(data) {
  const result = validateAssessment(data);
  const malicious = result.prediction === "malicious";
  busy(false); $("error").hidden = true; $("auth-state").hidden = true; $("input-view").hidden = true;
  const risk = displayRisk(result);
  $("risk").textContent = `${risk} risk`;
  $("result").dataset.risk = risk;
  $("verdict").textContent = malicious ? "Potentially malicious link detected" : "No malicious URL pattern detected";
  $("checked-url").textContent = result.url;
  $("full-url").textContent = result.url;
  document.querySelector(".url-details").open = false;
  $("probability").textContent = `${(result.malicious_probability * 100).toFixed(1)}%`;
  $("score").setAttribute("aria-valuenow", String(result.malicious_probability * 100));
  $("score").setAttribute("aria-valuetext", `${(result.malicious_probability * 100).toFixed(1)}% malicious probability`);
  $("score-fill").style.width = `${result.malicious_probability * 100}%`;
  $("safety").textContent = malicious
    ? "Avoid opening this link unless you trust its source and have independently verified the destination."
    : "No malicious URL pattern was detected by NurtureShield. This does not guarantee that the destination or its content is safe.";
  $("characteristics").replaceChildren(...result.observed_characteristics.map(text => {
    const li = document.createElement("li"); li.textContent = text; return li;
  }));
  $("no-characteristics").hidden = result.observed_characteristics.length > 0;
  $("result").hidden = false; $("verdict").focus();
}
$("url").addEventListener("input", () => { revision++; jobId = null; clearTimeout(pendingTimer); clearResult(); });
$("checker").addEventListener("submit", async event => {
  event.preventDefault(); clearResult();
  const current = ++revision;
  jobId = null; clearTimeout(pendingTimer);
  try {
    const url = validateUrl($("url").value);
    busy(true);
    const reply = await chrome.runtime.sendMessage({ type: "analyze", url });
    if (current !== revision) return;
    if (reply.error) showError(reply.error); else showResult(reply.result);
  } catch (error) { if (current === revision) showError({ code: error.code, message: error.code ? error.message : "The extension could not reach its service worker. Reopen it and try again." }); }
});
$("current-tab").addEventListener("click", async () => {
  clearResult();
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    $("url").value = validateUrl(tab?.url);
    revision++; jobId = null; clearTimeout(pendingTimer);
  } catch { showError({ message: "This tab’s URL is unavailable. Paste the link manually. No page contents were read." }); }
});
$("sign-in").addEventListener("click", () => chrome.tabs.create({ url: `${API_ORIGIN}/sign-in` }));
function resetCheck() {
  revision++; jobId = null; clearTimeout(pendingTimer); busy(false); clearResult();
  $("url").value = ""; $("url").focus();
}
$("another").addEventListener("click", resetCheck);
$("auth-retry").addEventListener("click", () => { clearResult(); $("url").focus(); });
async function refreshJob() {
  if (!jobId) return;
  const current = revision;
  try {
    const reply = await chrome.runtime.sendMessage({ type: "job", id: jobId });
    if (current !== revision || !jobId) return;
    if (reply.error) return showError(reply.error);
    const job = reply.job;
    $("url").value = job.url;
    clearTimeout(pendingTimer);
    if (job.phase === "done") showResult(job.result);
    else if (job.phase === "error") showError(job.error);
    else if (Date.now() - job.createdAt > 30000) showError({ message: "The check was interrupted. Press Check Link to retry." });
    else { busy(true); pendingTimer = setTimeout(refreshJob, 1000); }
  } catch { showError({ message: "Unable to recover this check. Press Check Link to retry." }); }
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && jobId && changes[`shield-job:${jobId}`]) void refreshJob();
});
void refreshJob();
