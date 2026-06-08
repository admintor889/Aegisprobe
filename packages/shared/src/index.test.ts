import { describe, expect, it } from "vitest";
import { sanitizeObservationText, summarizeOutput, parseTargetInput, validateReadablePath } from "./index.js";

describe("target parsing", () => {
  it("does not classify source/config filenames as domains", () => {
    expect(parseTargetInput("test.json").kind).toBe("text");
    expect(parseTargetInput("index.ts").kind).toBe("text");
    expect(parseTargetInput("config.yaml").kind).toBe("text");
  });

  it("still classifies real domain-like input as domain", () => {
    const target = parseTargetInput("example.com");
    expect(target.kind).toBe("domain");
    expect(target.normalized).toBe("example.com");
  });
});

describe("readable path validation", () => {
  it("blocks parent traversal outside the workspace", () => {
    const decision = validateReadablePath("..\\outside.txt");
    expect(decision.allowed).toBe(false);
  });

  it("blocks sensitive filenames", () => {
    const decision = validateReadablePath(".env");
    expect(decision.allowed).toBe(false);
  });
});

describe("observation text hygiene", () => {
  it("removes bulky HTML style, inline script, and data URL noise", () => {
    const noisy = [
      "HTTP/1.1 200 OK",
      "<style>body { color: red; } .icon { background: url(data:image/png;base64,AAAAAA==); }</style>",
      "<script>function noisy(){ return 'large inline logic'; }</script>",
      "<title>listing directory /files</title>",
      "<a href=\"report.md\">report.md</a>"
    ].join("\n");

    const sanitized = sanitizeObservationText(noisy);
    const summary = summarizeOutput(noisy);

    expect(sanitized).toContain("<style>[removed]</style>");
    expect(sanitized).toContain("<script>[removed inline script]</script>");
    expect(sanitized).not.toContain("large inline logic");
    expect(sanitized).not.toContain("AAAAAA==");
    expect(summary).toContain("report.md");
  });

  it("extracts actionable HTML signals before truncating page bodies", () => {
    const noisy = [
      "HTTP/1.1 200 OK",
      "<html><head><title>listing directory /files</title><style>",
      "x".repeat(4000),
      "</style></head><body>",
      "<a href=\"report.md\">report.md</a>",
      "<a href=\"backup.zip\">backup.zip</a>",
      "<script src=\"main.js\"></script>",
      "<form action=\"/login\"></form>",
      "</body></html>"
    ].join("");

    const summary = summarizeOutput(noisy, 600);

    expect(summary).toContain("Extracted signals:");
    expect(summary).toContain("Titles: listing directory /files");
    expect(summary).toContain("Links: report.md | backup.zip");
    expect(summary).toContain("Scripts: main.js");
    expect(summary).toContain("Forms: /login");
  });

  it("replaces binary HTTP bodies with a compact marker", () => {
    const output = [
      "HTTP/1.1 200 OK",
      "Content-Type: application/octet-stream",
      "Content-Length: 12",
      "",
      "\u0000\u0001KEEPASSDATA",
      "HTTP/1.1 404 Not Found",
      "",
      "<title>not found</title>"
    ].join("\n");

    const summary = summarizeOutput(output, 800);

    expect(summary).toContain("[binary body removed: 12 bytes]");
    expect(summary).not.toContain("KEEPASSDATA");
    expect(summary).toContain("HTTP/1.1 404 Not Found");
  });

  it("removes decoded binary noise lines that survive HTTP body replacement", () => {
    const summary = summarizeOutput(`normal\nabc\u0000\u0001\u0002binary\nstill text`, 800);

    expect(summary).toContain("normal");
    expect(summary).toContain("still text");
    expect(summary).toContain("[binary noise lines removed]");
    expect(summary).not.toContain("abc\u0000");
  });
});
