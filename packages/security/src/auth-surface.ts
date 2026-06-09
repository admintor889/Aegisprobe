import type { AuthSurfaceAssessment, BrowserCookieSignal, BrowserNetworkRequest, BrowserStorageItem, NormalizedApiEndpoint, WebAppReconResult } from "@aegisprobe/shared";

export function buildAuthSurfaceAssessment(result: WebAppReconResult): AuthSurfaceAssessment {
  const textCorpus = [
    result.startUrl,
    ...result.pagesVisited,
    ...(result.links ?? []),
    ...(result.apiEndpoints ?? []),
    ...result.apiInventory.map((item) => item.url),
    ...(result.normalizedApiEndpoints ?? []).flatMap((endpoint) => [endpoint.pathTemplate, ...endpoint.examples]),
    ...result.forms.flatMap((form) => [form.pageUrl, form.action, ...form.inputNames, ...form.inputTypes]),
    ...(result.buttons ?? []).flatMap((button) => [button.pageUrl, button.label, button.name ?? "", button.id ?? "", ...button.riskSignals]),
    ...(result.iframes ?? []).flatMap((frame) => [frame.pageUrl, frame.src, frame.name ?? "", frame.title ?? "", ...frame.riskSignals]),
    ...result.networkRequests.flatMap((request) => [request.url, request.method, request.status?.toString() ?? "", request.contentType ?? ""]),
    ...result.authSurface.notes
  ].join("\n");
  const lowerCorpus = textCorpus.toLowerCase();
  const mechanisms = inferSessionMechanisms(result);
  const riskSignals = inferAuthRiskSignals(result, mechanisms);
  const highValueFlows = inferHighValueFlows(result);
  const authState = inferAuthState(result, mechanisms);
  const meaningfulAuthEndpoints = result.authSurface.authEndpoints.filter(isAuthEndpoint);
  const loginPresent = result.authSurface.loginPages.length > 0
    || result.authSurface.passwordForms.length > 0
    || meaningfulAuthEndpoints.some((url) => /login|signin|session|token/i.test(authPath(url)));

  return {
    login: loginPresent ? "present" : "not_observed",
    registration: /(?:register|registration|signup|sign-up|create-account|join)(?:[./?#_-]|$)/i.test(lowerCorpus) ? "present" : "not_observed",
    passwordRecovery: /(?:forgot|reset|recover|recovery|password-reset|password\/reset)/i.test(lowerCorpus) ? "present" : "not_observed",
    oauthOrSso: /(?:oauth|openid|oidc|saml|sso|saml2|callback|authorize|authorization-code)/i.test(lowerCorpus) ? "present" : "not_observed",
    mfaOrCaptcha: /(?:mfa|2fa|otp|totp|captcha|recaptcha|hcaptcha|webauthn|passkey)/i.test(lowerCorpus) ? "present" : "not_observed",
    authState,
    sessionMechanisms: mechanisms.length > 0 ? mechanisms : ["unknown"],
    csrfSignals: inferCsrfSignals(result),
    loginPages: uniqueStrings(result.authSurface.loginPages),
    authEndpoints: uniqueStrings(meaningfulAuthEndpoints),
    highValueFlows,
    riskSignals,
    nextEvidenceNeeded: inferNextEvidenceNeeded(result, authState, highValueFlows, riskSignals),
    confidence: confidenceFor(result, mechanisms, riskSignals)
  };
}

function inferSessionMechanisms(result: WebAppReconResult): AuthSurfaceAssessment["sessionMechanisms"] {
  const mechanisms = new Set<AuthSurfaceAssessment["sessionMechanisms"][number]>();
  const storageItems = result.storageItems ?? result.storageSignals ?? [];
  const cookies = result.cookies ?? [];
  const requests = result.networkRequests ?? [];

  if (cookies.some(isSessionCookie) || requests.some((request) => Boolean(headerValue(request.requestHeaders, "cookie") || headerValue(request.responseHeaders, "set-cookie")))) {
    mechanisms.add("cookie");
  }
  if (storageItems.some((item) => /jwt|id[_-]?token|access[_-]?token|refresh[_-]?token|bearer/i.test(item.key))) {
    mechanisms.add("jwt");
  }
  if (storageItems.some((item) => item.storage === "localStorage" && /token|jwt|session|auth/i.test(item.key))) {
    mechanisms.add("localStorage");
  }
  if (storageItems.some((item) => item.storage === "sessionStorage" && /token|jwt|session|auth/i.test(item.key))) {
    mechanisms.add("sessionStorage");
  }
  if (requests.some((request) => Boolean(headerValue(request.requestHeaders, "authorization")))) {
    mechanisms.add("authorization-header");
  }
  return [...mechanisms];
}

function inferAuthRiskSignals(result: WebAppReconResult, mechanisms: AuthSurfaceAssessment["sessionMechanisms"]): string[] {
  const signals = new Set<string>();
  const storageItems = result.storageItems ?? result.storageSignals ?? [];
  const cookies = result.cookies ?? [];
  const httpsTarget = /^https:/i.test(result.startUrl);

  if (result.authSurface.passwordForms.some((form) => !form.hasCsrfToken)) {
    signals.add("password-form-without-csrf-token");
  }
  if (storageItems.some((item) => (item.storage === "localStorage" || item.storage === "sessionStorage") && /token|jwt|session|auth/i.test(item.key))) {
    signals.add("client-side-auth-token-storage");
  }
  if (mechanisms.includes("authorization-header")) {
    signals.add("authorization-header-observed");
  }
  for (const cookie of cookies.filter(isSessionCookie)) {
    if (cookie.httpOnly === false) signals.add("session-cookie-without-httponly");
    if (httpsTarget && cookie.secure === false) signals.add("session-cookie-without-secure");
    if (!cookie.sameSite || /^none$/i.test(cookie.sameSite)) signals.add("session-cookie-weak-samesite");
  }
  if ((result.normalizedApiEndpoints ?? []).some((endpoint) => endpoint.authRequired === "unknown" && endpoint.riskSignals.some((signal) => /admin|object|business|state-changing/i.test(signal)))) {
    signals.add("high-value-route-auth-unknown");
  }
  if (result.networkRequests.some((request) => isAuthEndpoint(request.url) && request.status !== undefined && request.status >= 400 && request.status < 500)) {
    signals.add("auth-endpoint-client-error-observed");
  }
  return [...signals].sort();
}

function inferHighValueFlows(result: WebAppReconResult): string[] {
  const flows = new Set<string>();
  const endpoints = result.normalizedApiEndpoints ?? [];
  for (const endpoint of endpoints) {
    const text = `${endpoint.method} ${endpoint.pathTemplate} ${endpoint.queryParams.join(" ")} ${endpoint.bodyParamHints.join(" ")} ${endpoint.riskSignals.join(" ")}`.toLowerCase();
    const prefix = `${endpoint.method} ${endpoint.pathTemplate}`;
    if (/admin|manage|role|permission/.test(text)) flows.add(`${prefix} | function-level authorization`);
    if (/\{id\}|\{uuid\}|tenant|org|workspace|account|user|order|invoice|ticket|project/.test(text)) flows.add(`${prefix} | object/tenant authorization`);
    if (/refund|payment|price|coupon|credit|transfer|withdraw|amount/.test(text)) flows.add(`${prefix} | financial workflow`);
    if (/reset|password|invite|email|mfa|2fa|otp|session|token/.test(text)) flows.add(`${prefix} | auth/session workflow`);
    if (/export|download|upload|file|attachment|share|delete/.test(text)) flows.add(`${prefix} | data/file lifecycle`);
  }
  if (flows.size === 0) {
    for (const item of result.apiInventory) {
      if (/admin|account|user|order|tenant|invoice|payment|refund|export|download|reset|session|token/i.test(item.url)) {
        flows.add(`${item.method ?? "ANY"} ${safePath(item.url)} | raw API high-value route`);
      }
    }
  }
  return [...flows].slice(0, 25);
}

function inferAuthState(result: WebAppReconResult, mechanisms: AuthSurfaceAssessment["sessionMechanisms"]): AuthSurfaceAssessment["authState"] {
  if (result.storageStatePath || mechanisms.some((mechanism) => mechanism === "authorization-header" || mechanism === "jwt" || mechanism === "localStorage" || mechanism === "sessionStorage")) {
    return "authenticated";
  }
  if (result.networkRequests.some((request) => isAuthEndpoint(request.url) && request.status !== undefined && [400, 401, 403, 422].includes(request.status))) {
    return "failed_login";
  }
  if (result.authSurface.passwordForms.length > 0 || result.authSurface.loginPages.length > 0 || result.authSurface.authEndpoints.some(isAuthEndpoint)) {
    return "anonymous";
  }
  return "unknown";
}

function inferCsrfSignals(result: WebAppReconResult): AuthSurfaceAssessment["csrfSignals"] {
  const passwordForms = result.authSurface.passwordForms;
  if (passwordForms.length === 0) return "not_applicable";
  if (passwordForms.some((form) => !form.hasCsrfToken)) return "missing_in_password_forms";
  if (passwordForms.some((form) => form.hasCsrfToken)) return "present";
  return "unknown";
}

function inferNextEvidenceNeeded(
  result: WebAppReconResult,
  authState: AuthSurfaceAssessment["authState"],
  highValueFlows: string[],
  riskSignals: string[]
): string[] {
  const needed = new Set<string>();
  const authorizationFlows = highValueFlows.filter((flow) => /object\/tenant authorization|function-level authorization/i.test(flow));
  if (authState !== "authenticated" && (result.authSurface.passwordForms.length > 0 || result.authSurface.authEndpoints.some(isAuthEndpoint))) {
    needed.add("Capture an authorized Playwright storage-state or register cookie/header auth context; do not attempt credential guessing.");
  }
  if (authorizationFlows.length > 0) {
    needed.add("Define expected role, tenant, and object ownership rules for high-value API flows.");
  }
  if (highValueFlows.length > 0 && authorizationFlows.length === 0) {
    needed.add("Define expected business rules, test-data boundaries, and mutation stop conditions for high-value API flows.");
  }
  if (authorizationFlows.length > 0 && authState !== "authenticated") {
    needed.add("Provide at least two approved roles/tenants before BOLA/BFLA/IDOR validation.");
  }
  if (riskSignals.includes("password-form-without-csrf-token")) {
    needed.add("Validate CSRF/session behavior only with explicit active-testing approval and a safe test account.");
  }
  if ((result.normalizedApiEndpoints ?? []).length === 0) {
    needed.add("Normalize API inventory before planning authorization matrix tests.");
  }
  return [...needed];
}

function confidenceFor(result: WebAppReconResult, mechanisms: AuthSurfaceAssessment["sessionMechanisms"], riskSignals: string[]): AuthSurfaceAssessment["confidence"] {
  const meaningfulAuthEndpointCount = result.authSurface.authEndpoints.filter(isAuthEndpoint).length;
  const signalCount = result.authSurface.loginPages.length
    + meaningfulAuthEndpointCount
    + result.authSurface.passwordForms.length
    + mechanisms.filter((mechanism) => mechanism !== "unknown").length
    + riskSignals.length;
  if (signalCount >= 4) return "high";
  if (signalCount >= 2) return "medium";
  return "low";
}

function isSessionCookie(cookie: BrowserCookieSignal): boolean {
  return /sid|sess|session|auth|token|jwt|remember|xsrf|csrf/i.test(cookie.name);
}

function headerValue(headers: Record<string, string> | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  const found = Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase());
  return found?.[1];
}

function isAuthEndpoint(url: string): boolean {
  return /\/(?:login|signin|logout|register|registration|signup|auth|session|token|oauth|sso|password|reset)(?:[./?_-]|$)/i.test(authPath(url));
}

function authPath(value: string): string {
  try {
    return new URL(value).pathname.split("/").map((segment) => segment.split(";")[0]).join("/");
  } catch {
    return value.split("?")[0]?.split("/").map((segment) => segment.split(";")[0]).join("/") ?? value;
  }
}

function safePath(value: string): string {
  try {
    const parsed = new URL(value);
    return parsed.pathname || value;
  } catch {
    return value;
  }
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim().length > 0))].sort();
}
