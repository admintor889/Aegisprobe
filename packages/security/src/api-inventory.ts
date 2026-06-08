import { type ApiDescriptionDocument, type BrowserNetworkRequest, type NormalizedApiEndpoint, type WebAppReconResult } from "@aegisprobe/shared";
import { uniqueBy, uniqueStrings } from "./utils.js";

type ApiInventorySource = NormalizedApiEndpoint["sources"][number];

type EndpointObservation = {
  url: string;
  method: string;
  source: ApiInventorySource;
  confidence: NormalizedApiEndpoint["confidence"];
  riskSignals: string[];
  queryParams: string[];
  bodyParamHints: string[];
  status?: number;
  contentType?: string;
};

type RouteShape = {
  origin: string;
  segments: string[];
  dynamic: boolean[];
};

const SENSITIVE_PARAM = /(?:pass(?:word)?|passwd|pwd|secret|token|jwt|bearer|authorization|auth|api[_-]?key|access[_-]?key|client[_-]?secret|session|cookie|csrf|xsrf|nonce|otp|mfa|2fa|code)/i;
const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function normalizeApiInventory(result: WebAppReconResult): NormalizedApiEndpoint[] {
  const observations = collectEndpointObservations(result);
  const routeShapes = new Map<string, RouteShape>();
  for (const observation of observations) {
    const parsed = safeUrl(observation.url, result.startUrl);
    if (!parsed) {
      continue;
    }
    routeShapes.set(observation.url, buildRouteShape(parsed));
  }
  refineRouteShapesByCluster(observations, routeShapes, result.startUrl);

  const groups = new Map<string, EndpointObservation[]>();
  for (const observation of observations) {
    const parsed = safeUrl(observation.url, result.startUrl);
    const shape = routeShapes.get(observation.url);
    if (!parsed || !shape) {
      continue;
    }
    const pathTemplate = renderPathTemplate(shape);
    const key = `${observation.method}:${shape.origin}:${pathTemplate}`;
    groups.set(key, [...(groups.get(key) ?? []), observation]);
  }

  const authEndpointSet = new Set(result.authSurface.authEndpoints
    .filter((url) => isAuthEndpointUrl(url, result.startUrl))
    .map((url) => normalizeUrlKey(url, result.startUrl))
    .filter((url): url is string => Boolean(url)));
  const passwordFormActions = new Set(result.authSurface.passwordForms.map((form) => normalizeUrlKey(form.action, result.startUrl)).filter((url): url is string => Boolean(url)));

  return [...groups.entries()].map(([key, group]) => {
    const first = group[0];
    const parsed = safeUrl(first.url, result.startUrl);
    const shape = routeShapes.get(first.url);
    const pathTemplate = shape ? renderPathTemplate(shape) : parsed?.pathname || "/";
    const riskSignals = uniqueStrings([
      ...group.flatMap((item) => item.riskSignals),
      ...derivedRiskSignals(group, pathTemplate, authEndpointSet, passwordFormActions, result.startUrl)
    ]).sort();
    return {
      id: `api_${stableHash(key)}`,
      method: first.method,
      pathTemplate,
      examples: uniqueStrings(group.map((item) => sanitizeExampleUrl(item.url, result.startUrl))).slice(0, 5),
      queryParams: sanitizeParamHints(group.flatMap((item) => item.queryParams)).sort(),
      bodyParamHints: sanitizeParamHints(group.flatMap((item) => item.bodyParamHints)).sort().slice(0, 30),
      sources: uniqueStrings(group.map((item) => item.source)).sort() as NormalizedApiEndpoint["sources"],
      authRequired: inferAuthRequired(group, pathTemplate, authEndpointSet, passwordFormActions, result.startUrl),
      confidence: mergeEndpointConfidence(group),
      riskSignals
    };
  }).sort((left, right) =>
    confidenceRank(right.confidence) - confidenceRank(left.confidence)
    || right.sources.length - left.sources.length
    || left.pathTemplate.localeCompare(right.pathTemplate)
    || left.method.localeCompare(right.method)
  );
}

function collectEndpointObservations(result: WebAppReconResult): EndpointObservation[] {
  const observations: EndpointObservation[] = [];
  for (const item of result.apiInventory) {
    const parsed = safeUrl(item.url, result.startUrl);
    if (!parsed) {
      continue;
    }
    observations.push({
      url: parsed.href,
      method: normalizeMethod(item.method),
      source: item.source,
      confidence: item.confidence,
      riskSignals: item.riskSignals,
      queryParams: queryParamNames(parsed),
      bodyParamHints: []
    });
  }
  for (const form of result.forms) {
    const parsed = safeUrl(form.action, result.startUrl);
    if (!parsed) {
      continue;
    }
    observations.push({
      url: parsed.href,
      method: normalizeMethod(form.method),
      source: "form",
      confidence: form.hasPassword || form.riskSignals?.length ? "medium" : "low",
      riskSignals: form.riskSignals ?? [],
      queryParams: sanitizeParamHints(queryParamNames(parsed).concat(normalizeMethod(form.method) === "GET" ? form.inputNames : [])),
      bodyParamHints: normalizeMethod(form.method) === "GET" ? [] : sanitizeParamHints(form.inputNames)
    });
  }
  for (const request of result.networkRequests) {
    const parsed = safeUrl(request.url, result.startUrl);
    if (!parsed) {
      continue;
    }
    if (request.resourceType !== "xhr" && request.resourceType !== "fetch" && !isApiLikeObservationUrl(parsed)) {
      continue;
    }
    observations.push({
      url: parsed.href,
      method: normalizeMethod(request.method),
      source: "network",
      confidence: "high",
      riskSignals: requestRiskSignals(request),
      queryParams: queryParamNames(parsed),
      bodyParamHints: bodyHintsFromNetworkRequest(request),
      status: request.status,
      contentType: request.contentType
    });
  }
  for (const endpoint of result.jsEndpoints) {
    const parsed = safeUrl(endpoint.normalizedUrl ?? endpoint.value, result.startUrl);
    if (!parsed) {
      continue;
    }
    observations.push({
      url: parsed.href,
      method: normalizeMethod(endpoint.method),
      source: "script",
      confidence: endpoint.confidence,
      riskSignals: endpoint.riskSignals,
      queryParams: queryParamNames(parsed),
      bodyParamHints: []
    });
  }
  observations.push(...collectApiDescriptionObservations(result));
  return uniqueBy(observations, (item) => `${item.source}:${item.method}:${item.url}:${item.status ?? ""}:${item.bodyParamHints.join(",")}`);
}

function collectApiDescriptionObservations(result: WebAppReconResult): EndpointObservation[] {
  const observations: EndpointObservation[] = [];
  for (const document of result.apiDescriptionDocuments ?? []) {
    if (document.kind === "graphql") {
      const parsed = safeUrl(document.url, result.startUrl);
      if (!parsed) continue;
      observations.push({
        url: parsed.href,
        method: "POST",
        source: "graphql",
        confidence: document.error ? "medium" : "high",
        riskSignals: uniqueStrings(["graphql-endpoint", ...apiDescriptionRiskSignals(document)]),
        queryParams: queryParamNames(parsed),
        bodyParamHints: ["query", "variables", "operationName"],
        status: document.status,
        contentType: document.contentType
      });
      continue;
    }

    const spec = parseJsonObject(document.document);
    if (!spec) continue;
    const paths = parseJsonObject(spec.paths);
    if (!paths) continue;
    const pathItemMethods = new Set(["get", "post", "put", "patch", "delete", "head", "options", "trace"]);
    const serverBase = openApiServerBase(spec, document.url, result.startUrl);
    for (const [path, pathItem] of Object.entries(paths)) {
      const pathObject = parseJsonObject(pathItem);
      if (!pathObject || !path.startsWith("/")) continue;
      const sharedParameters = Array.isArray(pathObject.parameters) ? pathObject.parameters : [];
      for (const [method, operation] of Object.entries(pathObject)) {
        const lowerMethod = method.toLowerCase();
        if (!pathItemMethods.has(lowerMethod)) continue;
        const operationObject = parseJsonObject(operation);
        const parameters = [...sharedParameters, ...(Array.isArray(operationObject?.parameters) ? operationObject.parameters : [])];
        const queryParams = parameters
          .map((parameter) => parseJsonObject(resolveOpenApiRef(spec, parameter)))
          .filter((parameter): parameter is Record<string, unknown> => Boolean(parameter))
          .filter((parameter) => stringValue(parameter.in) === "query")
          .map((parameter) => stringValue(parameter.name))
          .filter((value): value is string => Boolean(value));
        const bodyParamHints = requestBodyHints(spec, operationObject?.requestBody);
        const url = openApiOperationUrl(serverBase, path) ?? safeUrl(path, result.startUrl)?.href;
        if (!url) continue;
        observations.push({
          url,
          method: lowerMethod.toUpperCase(),
          source: "openapi",
          confidence: "high",
          riskSignals: uniqueStrings([
            "api-description",
            ...apiDescriptionRiskSignals(document),
            ...operationRiskSignals(operationObject)
          ]),
          queryParams,
          bodyParamHints,
          status: document.status,
          contentType: document.contentType
        });
      }
    }
  }
  return observations;
}

function refineRouteShapesByCluster(observations: EndpointObservation[], shapes: Map<string, RouteShape>, baseUrl: string): void {
  const buckets = new Map<string, EndpointObservation[]>();
  for (const observation of observations) {
    const parsed = safeUrl(observation.url, baseUrl);
    const shape = shapes.get(observation.url);
    if (!parsed || !shape) {
      continue;
    }
    const key = `${observation.method}:${shape.origin}:${shape.segments.length}`;
    buckets.set(key, [...(buckets.get(key) ?? []), observation]);
  }

  for (const bucket of buckets.values()) {
    for (let leftIndex = 0; leftIndex < bucket.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < bucket.length; rightIndex += 1) {
        const left = shapes.get(bucket[leftIndex].url);
        const right = shapes.get(bucket[rightIndex].url);
        if (!left || !right || left.segments.length !== right.segments.length) {
          continue;
        }
        const diffs = left.segments
          .map((segment, index) => segment === right.segments[index] ? -1 : index)
          .filter((index) => index >= 0);
        if (diffs.length !== 1) {
          continue;
        }
        const index = diffs[0];
        if (left.dynamic[index] || right.dynamic[index] || looksDynamicSegment(left.segments[index]) || looksDynamicSegment(right.segments[index])) {
          left.dynamic[index] = true;
          right.dynamic[index] = true;
        }
      }
    }
  }
}

function buildRouteShape(url: URL): RouteShape {
  const segments = normalizedPathSegments(url);
  return {
    origin: url.origin,
    segments,
    dynamic: segments.map((segment) => looksDynamicSegment(segment))
  };
}

function renderPathTemplate(shape: RouteShape): string {
  if (shape.segments.length === 0) {
    return "/";
  }
  const rendered = shape.segments.map((segment, index) => shape.dynamic[index] ? placeholderForSegment(segment) : encodePathSegment(segment));
  return `/${rendered.join("/")}`;
}

function placeholderForSegment(segment: string): string {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(segment)) return "{uuid}";
  if (/^\d{4}-\d{2}-\d{2}$/.test(segment)) return "{date}";
  if (/@/.test(segment)) return "{email}";
  if (/^(?:[0-9a-f]{16,}|[a-z0-9_-]{24,})$/i.test(segment)) return "{token}";
  return "{id}";
}

function looksDynamicSegment(segment: string): boolean {
  const decoded = decodeSegment(segment);
  if (!decoded || decoded.length > 80) return true;
  if (/^[:{].+[}]?$/.test(decoded)) return true;
  if (/^\d+$/.test(decoded)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(decoded)) return true;
  if (/^[0-9a-f]{16,}$/i.test(decoded)) return true;
  if (/^[0-9a-f]{24}$/i.test(decoded)) return true;
  if (/^\d{4}-\d{2}-\d{2}$/.test(decoded)) return true;
  if (/^[^@/\s]+@[^@/\s]+\.[^@/\s]+$/.test(decoded)) return true;
  if (/[0-9]/.test(decoded) && decoded.length >= 10 && /^[a-z0-9._~-]+$/i.test(decoded)) return true;
  return false;
}

function isApiLikeObservationUrl(url: URL): boolean {
  if (/\/(?:api|graphql|rest|rpc|v\d+|oauth|auth|admin|manage|actuator|swagger|openapi)(?:\/|\?|$)/i.test(url.pathname)) {
    return true;
  }
  return url.searchParams.size > 0 && !/\.(?:html?|css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map)$/i.test(url.pathname);
}

function derivedRiskSignals(
  group: EndpointObservation[],
  pathTemplate: string,
  authEndpointSet: Set<string>,
  passwordFormActions: Set<string>,
  baseUrl: string
): string[] {
  const signals: string[] = [];
  const lower = pathTemplate.toLowerCase();
  if (group.some((item) => STATE_CHANGING_METHODS.has(item.method))) signals.push("state-changing-method");
  if (/\{(?:id|uuid|token|email|date)\}/.test(pathTemplate)) signals.push("object-or-tokenized-path");
  if (/\/(?:admin|manage|console|settings|roles?|permissions?)(?:\/|$)/i.test(pathTemplate)) signals.push("privileged-route");
  if (/\/(?:login|signin|logout|register|reset|password|oauth|sso|token|session|auth)(?:\/|$)/i.test(pathTemplate)) signals.push("auth-surface");
  if (/\/(?:order|cart|payment|refund|coupon|invoice|checkout|tenant|org|workspace|invite|approval|upload|download|share)(?:\/|$)/i.test(pathTemplate)) signals.push("business-workflow-route");
  if (group.some((item) => item.status === 401 || item.status === 403)) signals.push("auth-gated-status");
  if (group.some((item) => normalizeUrlKey(item.url, baseUrl) && (authEndpointSet.has(normalizeUrlKey(item.url, baseUrl) as string) || passwordFormActions.has(normalizeUrlKey(item.url, baseUrl) as string)))) {
    signals.push("auth-surface");
  }
  if (group.flatMap((item) => [...item.queryParams, ...item.bodyParamHints]).some((name) => SENSITIVE_PARAM.test(name))) {
    signals.push("sensitive-parameter-name");
  }
  if (lower.includes("graphql")) signals.push("graphql-endpoint");
  return signals;
}

function inferAuthRequired(
  group: EndpointObservation[],
  pathTemplate: string,
  authEndpointSet: Set<string>,
  passwordFormActions: Set<string>,
  baseUrl: string
): NormalizedApiEndpoint["authRequired"] {
  const lower = pathTemplate.toLowerCase();
  if (/\/(?:login|signin|register|reset|forgot|oauth|sso|token)(?:\/|$)/i.test(pathTemplate)) {
    return "not_required";
  }
  if (group.some((item) => item.status === 401 || item.status === 403)) {
    return "likely";
  }
  if (/\/(?:logout|me|account|profile|settings|admin|manage|roles?|permissions?|orders?|tenant|org|workspace)(?:\/|$)/i.test(pathTemplate)) {
    return "likely";
  }
  if (group.some((item) => {
    const normalized = normalizeUrlKey(item.url, baseUrl);
    return normalized && (authEndpointSet.has(normalized) || passwordFormActions.has(normalized));
  })) {
    return lower.includes("logout") ? "likely" : "not_required";
  }
  return "unknown";
}

function mergeEndpointConfidence(group: EndpointObservation[]): NormalizedApiEndpoint["confidence"] {
  if (group.some((item) => item.source === "network") || group.length >= 3 || uniqueStrings(group.map((item) => item.source)).length >= 2) {
    return "high";
  }
  if (group.some((item) => item.confidence === "high") || group.some((item) => item.source === "form" || item.source === "script")) {
    return "medium";
  }
  return "low";
}

function bodyHintsFromNetworkRequest(request: BrowserNetworkRequest): string[] {
  const preview = request.requestBodyPreview?.trim();
  if (!preview) {
    return [];
  }
  const hints: string[] = [];
  const contentType = request.contentType?.split(";")[0]?.trim().toLowerCase();
  if (contentType) {
    hints.push(`content-type:${contentType}`);
  }
  if (preview.startsWith("{") || preview.startsWith("[")) {
    try {
      const parsed = JSON.parse(preview);
      return sanitizeParamHints([...hints, ...jsonShapeHints(parsed)]).slice(0, 30);
    } catch {
      hints.push("json-body");
    }
  }
  try {
    const params = new URLSearchParams(preview);
    for (const key of params.keys()) {
      hints.push(key);
    }
  } catch {
    if (preview.length > 0) {
      hints.push("raw-body");
    }
  }
  return sanitizeParamHints(hints).slice(0, 30);
}

function jsonShapeHints(value: unknown, prefix = ""): string[] {
  if (!value || typeof value !== "object") {
    return prefix ? [prefix] : ["json-body"];
  }
  if (Array.isArray(value)) {
    return value.length > 0 ? jsonShapeHints(value[0], prefix ? `${prefix}[]` : "[]") : [prefix ? `${prefix}[]` : "array-body"];
  }
  const hints: string[] = [];
  for (const [key, child] of Object.entries(value as Record<string, unknown>).slice(0, 20)) {
    const path = prefix ? `${prefix}.${key}` : key;
    hints.push(path);
    if (child && typeof child === "object" && !Array.isArray(child)) {
      hints.push(...jsonShapeHints(child, path).slice(0, 5));
    }
  }
  return hints.length > 0 ? hints : ["json-object"];
}

function openApiServerBase(spec: Record<string, unknown>, documentUrl: string, fallbackUrl: string): string {
  const servers = Array.isArray(spec.servers) ? spec.servers : [];
  const firstServer = servers
    .map((server) => parseJsonObject(server))
    .map((server) => stringValue(server?.url))
    .find((url): url is string => Boolean(url));
  if (firstServer) {
    const parsed = safeUrl(firstServer.replace(/\{[^}]+\}/g, ""), documentUrl);
    if (parsed) return parsed.href;
  }
  return documentUrl || fallbackUrl;
}

function openApiOperationUrl(serverBase: string, path: string): string | undefined {
  const parsed = safeUrl(serverBase, serverBase);
  if (!parsed) return undefined;
  const basePath = parsed.pathname.replace(/\/$/, "");
  parsed.pathname = `${basePath}${path}`;
  parsed.search = "";
  parsed.hash = "";
  return parsed.href;
}

function requestBodyHints(spec: Record<string, unknown>, requestBody: unknown): string[] {
  const body = parseJsonObject(resolveOpenApiRef(spec, requestBody));
  if (!body) return [];
  const hints: string[] = [];
  const content = parseJsonObject(body.content);
  if (content) {
    for (const [contentType, media] of Object.entries(content).slice(0, 8)) {
      hints.push(`content-type:${contentType.toLowerCase()}`);
      const mediaObject = parseJsonObject(media);
      hints.push(...schemaHints(spec, mediaObject?.schema).slice(0, 30));
    }
  }
  return uniqueStrings(hints).slice(0, 40);
}

function schemaHints(spec: Record<string, unknown>, schemaValue: unknown, prefix = ""): string[] {
  const schema = parseJsonObject(resolveOpenApiRef(spec, schemaValue));
  if (!schema) return prefix ? [prefix] : [];
  const type = stringValue(schema.type);
  if (type === "array") {
    return schemaHints(spec, schema.items, prefix ? `${prefix}[]` : "[]");
  }
  const properties = parseJsonObject(schema.properties);
  if (!properties) return prefix ? [prefix] : [];
  const hints: string[] = [];
  for (const [name, child] of Object.entries(properties).slice(0, 30)) {
    const path = prefix ? `${prefix}.${name}` : name;
    hints.push(path);
    const childObject = parseJsonObject(resolveOpenApiRef(spec, child));
    if (childObject?.properties) {
      hints.push(...schemaHints(spec, childObject, path).slice(0, 8));
    }
  }
  return uniqueStrings(hints);
}

function operationRiskSignals(operation: Record<string, unknown> | undefined): string[] {
  const text = [
    stringValue(operation?.operationId),
    stringValue(operation?.summary),
    stringValue(operation?.description),
    ...(Array.isArray(operation?.tags) ? operation.tags.filter((item): item is string => typeof item === "string") : [])
  ].filter(Boolean).join(" ");
  const signals: string[] = [];
  if (/admin|manage|role|permission|privilege/i.test(text)) signals.push("privileged-route");
  if (/login|signin|logout|oauth|token|session|password|mfa|otp/i.test(text)) signals.push("auth-surface");
  if (/order|invoice|payment|refund|checkout|tenant|workspace|approval|upload|download|share/i.test(text)) signals.push("business-workflow-route");
  return signals;
}

function apiDescriptionRiskSignals(document: ApiDescriptionDocument): string[] {
  const signals = ["api-description-source"];
  const text = `${document.url} ${document.title ?? ""}`;
  if (/swagger|openapi/i.test(text)) signals.push("openapi-description");
  if (/graphql/i.test(text)) signals.push("graphql-endpoint");
  return signals;
}

function resolveOpenApiRef(spec: Record<string, unknown>, value: unknown): unknown {
  const object = parseJsonObject(value);
  const ref = stringValue(object?.$ref);
  if (!ref?.startsWith("#/")) return value;
  return ref.slice(2).split("/").reduce<unknown>((current, part) => {
    const container = parseJsonObject(current);
    if (!container) return undefined;
    return container[part.replace(/~1/g, "/").replace(/~0/g, "~")];
  }, spec);
}

function parseJsonObject(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function requestRiskSignals(request: BrowserNetworkRequest): string[] {
  const signals: string[] = [];
  if (STATE_CHANGING_METHODS.has(normalizeMethod(request.method))) signals.push("state-changing-method");
  if (request.status === 401 || request.status === 403) signals.push("auth-gated-status");
  if (/json|graphql/i.test(request.contentType ?? "")) signals.push("structured-api-response");
  return signals;
}

function normalizeMethod(method?: string): string {
  const value = (method ?? "GET").trim().toUpperCase();
  return value || "GET";
}

function queryParamNames(url: URL): string[] {
  return sanitizeParamHints([...url.searchParams.keys()].filter(Boolean));
}

function sanitizeParamHints(values: string[]): string[] {
  return uniqueStrings(values
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
    .map((value) => looksSecretLikeParamHint(value) ? "[redacted-param-name]" : value));
}

function looksSecretLikeParamHint(value: string): boolean {
  const normalized = value.replace(/\[[^\]]+\]$/g, "");
  if (/^[a-f0-9]{16,}$/i.test(normalized)) return true;
  if (/^[A-Za-z0-9_-]{24,}$/.test(normalized) && /[0-9]/.test(normalized) && /[A-Za-z]/.test(normalized)) return true;
  if (/^eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}/.test(normalized)) return true;
  return false;
}

function sanitizeExampleUrl(value: string, baseUrl: string): string {
  const parsed = safeUrl(value, baseUrl);
  if (!parsed) {
    return value;
  }
  const output = new URL(`${parsed.origin}${stripPathMatrixParameters(parsed.pathname) || "/"}`);
  for (const key of parsed.searchParams.keys()) {
    output.searchParams.set(key, SENSITIVE_PARAM.test(key) ? "<redacted>" : "<value>");
  }
  return output.href;
}

function normalizeUrlKey(value: string, baseUrl: string): string | undefined {
  const parsed = safeUrl(value, baseUrl);
  return parsed ? `${parsed.origin}${stripPathMatrixParameters(parsed.pathname) || "/"}`.toLowerCase() : undefined;
}

function isAuthEndpointUrl(value: string, baseUrl: string): boolean {
  const parsed = safeUrl(value, baseUrl);
  if (!parsed) {
    return false;
  }
  const path = stripPathMatrixParameters(parsed.pathname);
  return /\/(?:login|signin|logout|register|reset|forgot|password|oauth|sso|token|session|auth|mfa|otp)(?:\/|$)/i.test(path);
}

function safeUrl(value: string, baseUrl: string): URL | undefined {
  try {
    return new URL(value, baseUrl);
  } catch {
    return undefined;
  }
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function normalizedPathSegments(url: URL): string[] {
  return stripPathMatrixParameters(url.pathname)
    .split("/")
    .filter(Boolean)
    .map((segment) => decodeSegment(segment));
}

function stripPathMatrixParameters(pathname: string): string {
  const normalized = pathname.split("/").map((segment) => {
    if (!segment) return segment;
    const decoded = decodeSegment(segment);
    const semicolonIndex = decoded.indexOf(";");
    if (semicolonIndex < 0) return segment;
    return encodePathSegment(decoded.slice(0, semicolonIndex));
  }).join("/");
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

function encodePathSegment(segment: string): string {
  return encodeURIComponent(segment).replace(/%2F/gi, "/");
}

function confidenceRank(confidence: NormalizedApiEndpoint["confidence"]): number {
  return ({ low: 0, medium: 1, high: 2 })[confidence];
}

function stableHash(value: string): string {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36);
}
