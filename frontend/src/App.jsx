import { useEffect, useState } from "react";

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

  useEffect(() => {
    fetch("http://127.0.0.1:8000/")
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
      const response = await fetch("http://127.0.0.1:8000/scan", {
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

      setFindings(data.findings);
      setScanned(true);
    } catch (err) {
      setScanError(err.message || "Unable to scan the code.");
    } finally {
      setLoading(false);
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
      }}
    >
      <h1>CodeGuard AI</h1>
      <p>AI-powered code analysis and security assistant</p>

      <hr />

      <h2>Backend Connection</h2>

      {error ? (
        <p style={{ color: "#dc2626" }}>{error}</p>
      ) : (
        <p style={{ color: "#15803d" }}>{message}</p>
      )}

      <hr />

      <h2>Security Code Scanner</h2>
      <p>Paste Python code below to check for security issues.</p>

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

      <button
        onClick={handleScan}
        disabled={loading || !code.trim()}
        style={{
          marginTop: "16px",
          padding: "12px 22px",
          border: "none",
          borderRadius: "6px",
          backgroundColor: loading ? "#9ca3af" : "#2563eb",
          color: "white",
          fontSize: "15px",
          fontWeight: "bold",
          cursor: loading ? "wait" : "pointer",
        }}
      >
        {loading ? "Scanning..." : "Scan Code"}
      </button>

      {scanError && (
        <p style={{ color: "#dc2626", marginTop: "16px" }}>
          Scan failed: {scanError}
        </p>
      )}

      {scanned && (
        <section style={{ marginTop: "28px" }}>
          <h2>Scan Results</h2>
          <p>
            Total findings: <strong>{findings.length}</strong>
          </p>

          {findings.length === 0 ? (
            <p>No issues detected by the currently configured rules.</p>
          ) : (
            findings.map((finding, index) => (
              <article
                key={`${finding.rule_id}-${finding.start_line}-${index}`}
                style={{
                  marginTop: "16px",
                  padding: "16px",
                  border: "1px solid #fca5a5",
                  borderRadius: "8px",
                  backgroundColor: "#fff7f7",
                }}
              >
                <h3 style={{ marginTop: 0 }}>
                  {finding.rule_id}
                </h3>

                <p>
                  <strong>Severity:</strong> {finding.severity}
                </p>
                <p>
                  <strong>Line:</strong> {finding.start_line}
                  {finding.end_line &&
                  finding.end_line !== finding.start_line
                    ? `–${finding.end_line}`
                    : ""}
                </p>
                <p>{finding.message}</p>

                <pre
                  style={{
                    padding: "12px",
                    overflowX: "auto",
                    backgroundColor: "#f3f4f6",
                    borderRadius: "4px",
                  }}
                >
                  <code>{finding.code_snippet}</code>
                </pre>
              </article>
            ))
          )}
        </section>
      )}

      <p
        style={{
          marginTop: "32px",
          fontSize: "13px",
          color: "#6b7280",
        }}
      >
        CodeGuard AI scans submitted source code without executing it.
        Results depend on the security rules currently configured.
      </p>
    </main>
  );
}

export default App;