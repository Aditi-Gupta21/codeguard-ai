import { useEffect, useState } from "react";

const API_BASE_URL = "http://127.0.0.1:8001";

function App() {
  const [message, setMessage] = useState("Connecting to backend...");
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");
  const [code, setCode] = useState(
    "user_input = input('Enter expression: ')\nresult = eval(user_input)\nprint(result)"
  );
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanned, setScanned] = useState(false);
  const [exporting, setExporting] = useState(false);

  const errorCount = findings.filter(
    (finding) => finding.severity?.toUpperCase() === "ERROR"
  ).length;

  const warningCount = findings.filter(
    (finding) => finding.severity?.toUpperCase() === "WARNING"
  ).length;

  const infoCount = findings.filter(
    (finding) => finding.severity?.toUpperCase() === "INFO"
  ).length;

  useEffect(() => {
    fetch(`${API_BASE_URL}/`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("Backend request failed");
        }
        return response.json();
      })
      .then((data) => {
        setMessage(data.message);
        setConnected(true);
        setError("");
      })
      .catch(() => {
        setError("Unable to connect to backend at " + API_BASE_URL);
        setConnected(false);
      });
  }, []);

  async function handleScan() {
    setLoading(true);
    setScanError("");
    setFindings([]);
    setScanned(false);

    try {
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "The scan request failed."
        );
      }

      setFindings(data.findings ?? []);
      setScanned(true);
    } catch (err) {
      setScanError(err.message || "Unable to scan the code.");
    } finally {
      setLoading(false);
    }
  }

  async function handleExport() {
    setExporting(true);
    try {
      const response = await fetch(`${API_BASE_URL}/scan/report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code }),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Export failed."
        );
      }

      const report = await response.json();
      const blob = new Blob([JSON.stringify(report, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "codeguard-report.json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setScanError(err.message || "Unable to export report.");
    } finally {
      setExporting(false);
    }
  }

  const summaryCards = [
    {
      label: "Total Findings",
      value: findings.length,
      color: "#1d4ed8",
      bgColor: "#eff6ff",
    },
    {
      label: "Errors",
      value: errorCount,
      color: "#b91c1c",
      bgColor: "#fef2f2",
    },
    {
      label: "Warnings",
      value: warningCount,
      color: "#b45309",
      bgColor: "#fffbeb",
    },
    {
      label: "Informational",
      value: infoCount,
      color: "#0f766e",
      bgColor: "#f0fdfa",
    },
  ];

  function getSeverityTheme(severity) {
    switch (severity?.toUpperCase()) {
      case "ERROR":
        return {
          border: "#b91c1c",
          badgeBg: "#fee2e2",
          badgeBorder: "#f87171",
          badgeText: "#7f1d1d",
          accentColor: "#b91c1c",
        };
      case "WARNING":
        return {
          border: "#b45309",
          badgeBg: "#fef3c7",
          badgeBorder: "#f59e0b",
          badgeText: "#78350f",
          accentColor: "#b45309",
        };
      case "INFO":
        return {
          border: "#0f766e",
          badgeBg: "#e0f2fe",
          badgeBorder: "#38bdf8",
          badgeText: "#075985",
          accentColor: "#0f766e",
        };
      default:
        return {
          border: "#475569",
          badgeBg: "#f1f5f9",
          badgeBorder: "#94a3b8",
          badgeText: "#1e293b",
          accentColor: "#475569",
        };
    }
  }

  return (
    <div style={{ backgroundColor: "#f1f5f9", minHeight: "100vh", padding: "40px 16px" }}>
      <main
        style={{
          maxWidth: "1040px",
          margin: "0 auto",
          padding: "36px",
          backgroundColor: "#ffffff",
          borderRadius: "12px",
          border: "1px solid #cbd5e1",
          boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 2px 4px -2px rgba(0, 0, 0, 0.05)",
          color: "#0f172a",
        }}
      >
        {/* Header */}
        <header
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            flexWrap: "wrap",
            gap: "16px",
            paddingBottom: "24px",
            borderBottom: "2px solid #e2e8f0",
          }}
        >
          <div>
            <h1
              style={{
                margin: 0,
                fontSize: "30px",
                fontWeight: "800",
                color: "#0f172a",
                letterSpacing: "-0.5px",
              }}
            >
              CodeGuard AI
            </h1>
            <p
              style={{
                margin: "6px 0 0",
                fontSize: "15px",
                color: "#334155",
                fontWeight: "500",
              }}
            >
              AI-Powered Static Code Analysis & Security Vulnerability Scanner
            </p>
          </div>

          {/* Backend Status Pill */}
          <div
            role="status"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              padding: "8px 16px",
              borderRadius: "9999px",
              fontSize: "14px",
              fontWeight: "600",
              backgroundColor: connected ? "#dcfce7" : "#fee2e2",
              border: `1px solid ${connected ? "#86efac" : "#fca5a5"}`,
              color: connected ? "#14532d" : "#7f1d1d",
            }}
          >
            <span
              style={{
                display: "inline-block",
                width: "9px",
                height: "9px",
                borderRadius: "50%",
                backgroundColor: connected ? "#16a34a" : "#dc2626",
              }}
            />
            {error || message}
          </div>
        </header>

        {/* Scanner Input Section */}
        <section style={{ marginTop: "28px" }}>
          <div style={{ marginBottom: "12px" }}>
            <label
              htmlFor="code-input"
              style={{
                display: "block",
                fontSize: "16px",
                fontWeight: "700",
                color: "#0f172a",
                marginBottom: "4px",
              }}
            >
              Source Code
            </label>
            <p style={{ margin: 0, fontSize: "14px", color: "#334155" }}>
              Paste Python source code below to detect security vulnerabilities, command injection, and exposed secrets.
            </p>
          </div>

          <textarea
            id="code-input"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            spellCheck={false}
            rows={12}
            style={{
              display: "block",
              width: "100%",
              boxSizing: "border-box",
              padding: "16px",
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
              fontSize: "14px",
              lineHeight: "1.6",
              color: "#0f172a",
              backgroundColor: "#f8fafc",
              border: "2px solid #cbd5e1",
              borderRadius: "8px",
              resize: "vertical",
              outline: "none",
            }}
            onFocus={(e) => (e.target.style.borderColor = "#1d4ed8")}
            onBlur={(e) => (e.target.style.borderColor = "#cbd5e1")}
          />

          {/* Action Buttons */}
          <div style={{ display: "flex", gap: "12px", marginTop: "16px", flexWrap: "wrap" }}>
            <button
              id="scan-button"
              onClick={handleScan}
              disabled={loading || !code.trim()}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "8px",
                padding: "12px 24px",
                border: "none",
                borderRadius: "6px",
                backgroundColor: loading || !code.trim() ? "#94a3b8" : "#1d4ed8",
                color: "#ffffff",
                fontSize: "15px",
                fontWeight: "700",
                cursor: loading || !code.trim() ? "not-allowed" : "pointer",
                boxShadow: "0 1px 2px 0 rgba(0, 0, 0, 0.05)",
                transition: "background-color 0.15s ease",
              }}
              onMouseEnter={(e) => {
                if (!loading && code.trim()) e.target.style.backgroundColor = "#1e40af";
              }}
              onMouseLeave={(e) => {
                if (!loading && code.trim()) e.target.style.backgroundColor = "#1d4ed8";
              }}
            >
              {loading ? "Scanning Source Code..." : "Scan Code"}
            </button>

            {scanned && (
              <button
                id="export-button"
                onClick={handleExport}
                disabled={exporting || !code.trim()}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "8px",
                  padding: "12px 24px",
                  border: "2px solid #1d4ed8",
                  borderRadius: "6px",
                  backgroundColor: exporting ? "#f1f5f9" : "#ffffff",
                  color: "#1d4ed8",
                  fontSize: "15px",
                  fontWeight: "700",
                  cursor: exporting || !code.trim() ? "not-allowed" : "pointer",
                  transition: "all 0.15s ease",
                }}
                onMouseEnter={(e) => {
                  if (!exporting && code.trim()) {
                    e.target.style.backgroundColor = "#eff6ff";
                  }
                }}
                onMouseLeave={(e) => {
                  if (!exporting && code.trim()) {
                    e.target.style.backgroundColor = "#ffffff";
                  }
                }}
              >
                {exporting ? "Generating Report..." : "Export JSON Report"}
              </button>
            )}
          </div>

          {/* Scan Error Message */}
          {scanError && (
            <div
              role="alert"
              style={{
                marginTop: "16px",
                padding: "16px",
                backgroundColor: "#fef2f2",
                border: "1px solid #f87171",
                borderRadius: "8px",
                color: "#7f1d1d",
                fontWeight: "600",
              }}
            >
              <strong>Scan Error:</strong> {scanError}
            </div>
          )}
        </section>

        {/* Results Section */}
        {scanned && (
          <section style={{ marginTop: "36px", paddingTop: "28px", borderTop: "2px solid #e2e8f0" }}>
            <h2
              style={{
                margin: 0,
                fontSize: "22px",
                fontWeight: "800",
                color: "#0f172a",
              }}
            >
              Scan Results
            </h2>
            <p style={{ margin: "4px 0 20px", fontSize: "14px", color: "#334155" }}>
              Summary of detected issues, risk severities, and suggested remediations.
            </p>

            {/* Summary Metrics */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                gap: "14px",
                marginBottom: "28px",
              }}
            >
              {summaryCards.map((item) => (
                <div
                  key={item.label}
                  style={{
                    padding: "20px",
                    backgroundColor: "#ffffff",
                    border: "1px solid #cbd5e1",
                    borderTop: `4px solid ${item.color}`,
                    borderRadius: "8px",
                    boxShadow: "0 1px 3px rgba(0, 0, 0, 0.05)",
                  }}
                >
                  <p
                    style={{
                      margin: 0,
                      fontSize: "13px",
                      fontWeight: "700",
                      color: "#334155",
                      textTransform: "uppercase",
                      letterSpacing: "0.5px",
                    }}
                  >
                    {item.label}
                  </p>
                  <p
                    style={{
                      margin: "8px 0 0",
                      fontSize: "32px",
                      fontWeight: "800",
                      color: item.color,
                      lineHeight: 1,
                    }}
                  >
                    {item.value}
                  </p>
                </div>
              ))}
            </div>

            {/* Findings List or Clean State */}
            {findings.length === 0 ? (
              <div
                role="status"
                style={{
                  padding: "32px 24px",
                  backgroundColor: "#f0fdf4",
                  border: "2px solid #86efac",
                  borderRadius: "10px",
                  textAlign: "center",
                }}
              >
                <h3
                  style={{
                    margin: 0,
                    fontSize: "18px",
                    fontWeight: "800",
                    color: "#14532d",
                  }}
                >
                  No Security Issues Detected
                </h3>
                <p
                  style={{
                    margin: "8px 0 0",
                    fontSize: "14px",
                    color: "#166534",
                    lineHeight: 1.5,
                  }}
                >
                  The static analyzer did not identify any known vulnerability patterns in this snippet.
                </p>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                {findings.map((finding, index) => {
                  const theme = getSeverityTheme(finding.severity);

                  return (
                    <article
                      key={`${finding.rule_id}-${finding.start_line}-${index}`}
                      style={{
                        padding: "24px",
                        backgroundColor: "#ffffff",
                        border: "1px solid #cbd5e1",
                        borderLeft: `6px solid ${theme.border}`,
                        borderRadius: "8px",
                        boxShadow: "0 2px 4px rgba(0, 0, 0, 0.04)",
                      }}
                    >
                      {/* Finding Card Header */}
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          flexWrap: "wrap",
                          gap: "12px",
                          paddingBottom: "14px",
                          borderBottom: "1px solid #e2e8f0",
                        }}
                      >
                        <h3
                          style={{
                            margin: 0,
                            fontSize: "18px",
                            fontWeight: "800",
                            color: "#0f172a",
                            fontFamily: "ui-monospace, monospace",
                          }}
                        >
                          {finding.rule_id}
                        </h3>

                        <span
                          style={{
                            display: "inline-block",
                            padding: "4px 12px",
                            backgroundColor: theme.badgeBg,
                            border: `1px solid ${theme.badgeBorder}`,
                            borderRadius: "9999px",
                            fontSize: "12px",
                            fontWeight: "800",
                            color: theme.badgeText,
                            letterSpacing: "0.5px",
                          }}
                        >
                          {finding.severity}
                        </span>
                      </div>

                      {/* Finding Metadata Grid */}
                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                          gap: "10px",
                          margin: "16px 0",
                          fontSize: "14px",
                        }}
                      >
                        <div>
                          <strong style={{ color: "#0f172a" }}>Category:</strong>{" "}
                          <span style={{ color: "#334155", fontWeight: "600" }}>
                            {finding.category || "Security"}
                          </span>
                        </div>
                        <div>
                          <strong style={{ color: "#0f172a" }}>File:</strong>{" "}
                          <span style={{ color: "#334155", fontFamily: "monospace" }}>
                            {finding.file_path || "sample.py"}
                          </span>
                        </div>
                        <div>
                          <strong style={{ color: "#0f172a" }}>Line Range:</strong>{" "}
                          <span style={{ color: "#334155", fontWeight: "600" }}>
                            Line {finding.start_line ?? "Unknown"}
                            {finding.end_line != null && finding.end_line !== finding.start_line
                              ? `–${finding.end_line}`
                              : ""}
                          </span>
                        </div>
                      </div>

                      {/* Explanation */}
                      <div style={{ marginTop: "14px" }}>
                        <h4
                          style={{
                            margin: "0 0 6px",
                            fontSize: "14px",
                            fontWeight: "700",
                            color: "#0f172a",
                            textTransform: "uppercase",
                            letterSpacing: "0.3px",
                          }}
                        >
                          Explanation
                        </h4>
                        <p
                          style={{
                            margin: 0,
                            fontSize: "14px",
                            lineHeight: "1.6",
                            color: "#1e293b",
                          }}
                        >
                          {finding.message || "No explanation provided."}
                        </p>
                      </div>

                      {/* Affected Code Block */}
                      <div style={{ marginTop: "16px" }}>
                        <h4
                          style={{
                            margin: "0 0 6px",
                            fontSize: "14px",
                            fontWeight: "700",
                            color: "#0f172a",
                            textTransform: "uppercase",
                            letterSpacing: "0.3px",
                          }}
                        >
                          Affected Code Snippet
                        </h4>
                        <pre
                          style={{
                            margin: 0,
                            padding: "14px 18px",
                            backgroundColor: "#0f172a",
                            color: "#f8fafc",
                            border: "1px solid #1e293b",
                            borderRadius: "6px",
                            fontSize: "13px",
                            lineHeight: "1.6",
                            overflowX: "auto",
                            whiteSpace: "pre-wrap",
                          }}
                        >
                          <code>{finding.code_snippet || "No snippet available."}</code>
                        </pre>
                      </div>

                      {/* Recommended Remediation Box */}
                      <div
                        style={{
                          marginTop: "16px",
                          padding: "16px 20px",
                          backgroundColor: "#eff6ff",
                          border: "1px solid #93c5fd",
                          borderRadius: "6px",
                        }}
                      >
                        <h4
                          style={{
                            margin: "0 0 6px",
                            fontSize: "14px",
                            fontWeight: "800",
                            color: "#1e3a8a",
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                          }}
                        >
                          <span aria-hidden="true">✔</span> Recommended Remediation
                        </h4>
                        <p
                          style={{
                            margin: 0,
                            fontSize: "14px",
                            lineHeight: "1.6",
                            color: "#1e3a8a",
                            fontWeight: "500",
                          }}
                        >
                          {finding.remediation || "Follow secure coding practices."}
                        </p>
                      </div>
                    </article>
                  );
                })}
              </div>
            )}
          </section>
        )}

        {/* Footer */}
        <footer
          style={{
            marginTop: "40px",
            paddingTop: "20px",
            borderTop: "1px solid #e2e8f0",
            fontSize: "13px",
            lineHeight: "1.6",
            color: "#475569",
            textAlign: "center",
          }}
        >
          CodeGuard AI performs static security analysis without code execution. Findings depend on configured rule sets.
        </footer>
      </main>
    </div>
  );
}

export default App;
