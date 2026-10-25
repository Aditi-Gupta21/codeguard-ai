import { useEffect, useState } from "react";

function App() {
  const [message, setMessage] = useState("Connecting to backend...");
  const [error, setError] = useState("");

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

  return (
    <main style={{ padding: "32px", fontFamily: "Arial, sans-serif" }}>
      <h1>CodeGuard AI</h1>
      <p>AI-powered code analysis and security assistant</p>

      <hr />

      <h2>Backend Connection</h2>

      {error ? (
        <p style={{ color: "red" }}>{error}</p>
      ) : (
        <p>{message}</p>
      )}
    </main>
  );
}

export default App;