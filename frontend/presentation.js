// Extension presentation only. Never change the backend's classification or probability.
// Under the corrected backend contract: legitimate (<0.30) => low;
// malicious [0.30,0.50) => moderate; [0.50,0.80) => elevated; >=0.80 => high.
// Classification is authoritative, so a legitimate response always gets the calm low band.
export function displayRisk(result) {
  if (result.prediction === "legitimate") return "low";
  if (result.malicious_probability >= 0.80) return "high";
  if (result.malicious_probability >= 0.50) return "elevated";
  return "moderate";
}

export function displayError(error) {
  const messages = {
    auth: "Sign in to NurtureNet to check links with NurtureShield.",
    forbidden: "This check isn’t available for your account. Please try again or contact support.",
    network: "We couldn’t reach NurtureNet. Please try again shortly.",
    service: "NurtureShield is temporarily unavailable. Please try again shortly.",
    response: "We couldn’t read this result. Please try again.",
    timeout: "This check is taking longer than expected. Please try again.",
    rate: "You’ve made several checks. Please wait a moment and try again.",
    expired: "This check has expired. Please check the link again.",
  };
  if (messages[error?.code]) return messages[error.code];
  if (error?.code === "validation") return "Paste a valid web address to check.";
  return "We couldn’t complete this check. Please try again.";
}
