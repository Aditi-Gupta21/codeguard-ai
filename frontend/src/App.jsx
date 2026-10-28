import { useEffect, useState } from "react";

const API_BASE_URL = "http://127.0.0.1:8001";

function App() {
  const [message, setMessage] = useState("Connecting to backend...");
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
        setError("");
      })
      .catch(() => {
        setError("Unable to connect to the backend.");
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
      color: "#2563eb",
    },
    {
      label: "Errors",
      value: errorCount,
      color: "#dc2626",
    },
    {
      label: "Warnings",
      value: warningCount,
      color: "#d97706",
    },
    {
      label: "Informational",
      value: infoCount,
      color: "#0891b2",
    },
  ];

  function getSeverityColor(severity) {
    switch (severity?.toUpperCase()) {
      case "ERROR":
        return "#dc2626";
      case "WARNING":
        return "#d97706";
      case "INFO":
        return "#0891b2";
      default:
        return "#6b7280";
    }
  }

  return (
    <main
      style={{
        maxWidth: "1000px",
        margin: "0 auto",
        padding: "32px",
        fontFamily: "Arial, sans-serif",
        color: "#1f2937",
        backgroundColor: "#ffffff",
        minHeight: "100vh",
      }}
    >
      <header>
        <h1 style={{ marginBottom: "8px" }}>CodeGuard AI</h1>
        <p style={{ color: "#4b5563", marginTop: 0 }}>
          AI-powered code analysis and security assistant
        </p>
      </header>

      <hr style={{ border: 0, borderTop: "1px solid #e5e7eb" }} />

      <section>
        <h2>Backend Connection</h2>

        {error ? (
          <p style={{ color: "#dc2626" }}>{error}</p>
        ) : (
          <p style={{ color: "#15803d" }}>
            <span aria-hidden="true">● </span>
            {message}
          </p>
        )}
      </section>

      <hr style={{ border: 0, borderTop: "1px solid #e5e7eb" }} />

      <section>
        <h2>Security Code Scanner</h2>
        <p style={{ color: "#4b5563" }}>
          Paste Python code below to check for potential security issues.
        </p>

        <label htmlFor="code-input">
          <strong>Source Code</strong>
        </label>

        <textarea
          id="code-input"
          value={code}
          onChange={(event) => setCode(event.target.value)}
          spellCheck={false}
          rows={12}
          style={{
            display: "block",
            boxSizing: "border-box",
            width: "100%",
            marginTop: "10px",
            padding: "14px",
            fontFamily: "Consolas, monospace",
            fontSize: "14px",
            lineHeight: 1.6,
            border: "1px solid #9ca3af",
            borderRadius: "8px",
            backgroundColor: "#f9fafb",
            color: "#111827",
            resize: "vertical",
          }}
        />

        <div style={{ display: "flex", gap: "12px", marginTop: "16px" }}>
          <button
            id="scan-button"
            onClick={handleScan}
            disabled={loading || !code.trim()}
            style={{
              padding: "12px 22px",
              border: "none",
              borderRadius: "6px",
              backgroundColor: loading ? "#9ca3af" : "#2563eb",
              color: "#ffffff",
              fontSize: "15px",
              fontWeight: "bold",
              cursor: loading || !code.trim() ? "not-allowed" : "pointer",
            }}
          >
            {loading ? "Scanning..." : "Scan Code"}
          </button>

          {scanned && (
            <button
              id="export-button"
              onClick={handleExport}
              disabled={exporting || !code.trim()}
              style={{
                padding: "12px 22px",
                border: "1px solid #2563eb",
                borderRadius: "6px",
                backgroundColor: exporting ? "#e5e7eb" : "#ffffff",
                color: "#2563eb",
                fontSize: "15px",
                fontWeight: "bold",
                cursor: exporting || !code.trim() ? "not-allowed" : "pointer",
              }}
            >
              {exporting ? "Exporting..." : "Export JSON Report"}
            </button>
          )}
        </div>

        {scanError && (
          <p
            role="alert"
            style={{
              color: "#dc2626",
              marginTop: "16px",
              padding: "12px",
              backgroundColor: "#fef2f2",
              borderRadius: "6px",
            }}
          >
            Scan failed: {scanError}
          </p>
        )}
      </section>

      {scanned && (
        <section style={{ marginTop: "32px" }}>
          <h2>Scan Results</h2>
          <p style={{ color: "#4b5563" }}>
            Review the findings below, including their severity and
            recommended remediation.
          </p>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
              gap: "14px",
              margin: "20px 0",
            }}
          >
            {summaryCards.map((item) => (
              <div
                key={item.label}
                style={{
                  padding: "18px",
                  border: "1px solid #d1d5db",
                  borderRadius: "10px",
                  backgroundColor: "#ffffff",
                  borderTop: `4px solid ${item.color}`,
                }}
              >
                <p
                  style={{
                    margin: 0,
                    color: "#4b5563",
                    fontSize: "14px",
                  }}
                >
                  {item.label}
                </p>
                <p
                  style={{
                    margin: "8px 0 0",
                    fontSize: "28px",
                    fontWeight: "bold",
                    color: item.color,
                  }}
                >
                  {item.value}
                </p>
              </div>
            ))}
          </div>

          {findings.length === 0 ? (
            <div
              role="status"
              style={{
                marginTop: "20px",
                padding: "24px",
                border: "1px solid #86efac",
                borderRadius: "10px",
                backgroundColor: "#f0fdf4",
                textAlign: "center",
              }}
            >
              <h3 style={{ color: "#166534", marginTop: 0 }}>
                No issues detected
              </h3>
              <p style={{ color: "#166534", marginBottom: 0 }}>
                The configured security rules did not identify any issues
                in this code. This does not guarantee that the code is
                completely secure.
              </p>
            </div>
          ) : (
            findings.map((finding, index) => {
              const severityColor = getSeverityColor(finding.severity);

              return (
                <article
                  key={`${finding.rule_id}-${finding.start_line}-${index}`}
                  style={{
                    marginTop: "18px",
                    padding: "20px",
                    border: "1px solid #d1d5db",
                    borderLeft: `5px solid ${severityColor}`,
                    borderRadius: "8px",
                    backgroundColor: "#ffffff",
                    boxShadow: "0 2px 5px rgba(0, 0, 0, 0.04)",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "flex-start",
                      gap: "12px",
                      flexWrap: "wrap",
                    }}
                  >
                    <h3
                      style={{
                        margin: 0,
                        overflowWrap: "anywhere",
                      }}
                    >
                      {finding.rule_id}
                    </h3>

                    <span
                      style={{
                        padding: "5px 10px",
                        borderRadius: "20px",
                        backgroundColor: `${severityColor}15`,
                        color: severityColor,
                        fontSize: "12px",
                        fontWeight: "bold",
                      }}
                    >
                      {finding.severity}
                    </span>
                  </div>

                  <p>
                    <strong>Category:</strong>{" "}
                    {finding.category || "Security"}
                  </p>

                  <p>
                    <strong>File:</strong>{" "}
                    {finding.file_path || "sample.py"}
                  </p>

                  <p>
                    <strong>Line:</strong> {finding.start_line ?? "Unknown"}
                    {finding.end_line != null &&
                    finding.end_line !== finding.start_line
                      ? `–${finding.end_line}`
                      : ""}
                  </p>

                  <div style={{ marginTop: "16px" }}>
                    <h4 style={{ marginBottom: "6px" }}>Explanation</h4>
                    <p style={{ marginTop: 0, lineHeight: 1.6 }}>
                      {finding.message || "No explanation provided."}
                    </p>
                  </div>

                  <div style={{ marginTop: "16px" }}>
                    <h4 style={{ marginBottom: "8px" }}>Affected Code</h4>
                    <pre
                      style={{
                        padding: "14px",
                        overflowX: "auto",
                        whiteSpace: "pre-wrap",
                        overflowWrap: "anywhere",
                        backgroundColor: "#f3f4f6",
                        borderRadius: "6px",
                        fontSize: "13px",
                        lineHeight: 1.6,
                      }}
                    >
                      <code>{finding.code_snippet || "No snippet available."}</code>
                    </pre>
                  </div>

                  <div
                    style={{
                      marginTop: "16px",
                      padding: "14px",
                      borderRadius: "6px",
                      backgroundColor: "#eff6ff",
                      border: "1px solid #bfdbfe",
                    }}
                  >
                    <h4
                      style={{
                        marginTop: 0,
                        marginBottom: "8px",
                        color: "#1d4ed8",
                      }}
                    >
                      Recommended Remediation
                    </h4>
                    <p
                      style={{
                        margin: 0,
                        lineHeight: 1.6,
                        color: "#1e3a8a",
                      }}
                    >
                      {finding.remediation ||
                        "Review this finding and follow secure coding practices."}
                    </p>
                  </div>
                </article>
              );
            })
          )}
        </section>
      )}

      <footer
        style={{
          marginTop: "36px",
          paddingTop: "16px",
          borderTop: "1px solid #e5e7eb",
          fontSize: "13px",
          lineHeight: 1.6,
          color: "#6b7280",
        }}
      >
        CodeGuard AI scans submitted source code without executing it.
        Results depend on the configured security rules and may not identify
        every vulnerability.
      </footer>
    </main>
  );
}

export default App;