import React, { useState, useEffect } from "react";

const API = "http://127.0.0.1:8000";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [reportLoading, setReportLoading] = useState(false);

  const loadHistory = async () => {
    try {
      const response = await fetch(`${API}/history`);
      if (!response.ok) throw new Error("Could not load scan history");

      const data = await response.json();
      setHistory(
        data.map((item) => ({
          ...item,
          prediction: item.prediction || "good",
          ml_phishing_score: Number(item.ml_phishing_score ?? 0),
          risk_score: Number(item.risk_score ?? 0),
          risk_level: item.risk_level || "LOW",
        }))
      );
    } catch (err) {
      console.error("History error:", err);
      setError("Unable to load scan history. Check the backend connection.");
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const checkPhishing = async () => {
    if (!url.trim()) {
      setError("Please enter a URL to scan.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "URL scanning failed.");
      }

      setResult(data);
      setUrl("");
      await loadHistory();
    } catch (err) {
      setError(err.message || "Backend connection failed.");
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async () => {
    setReportLoading(true);
    setError("");

    try {
      const response = await fetch(`${API}/generate-report`);
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || "Could not generate report.");
      }

      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = downloadUrl;
      link.download = "PhishGuard_Report.pdf";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
    } catch (err) {
      setError(err.message || "Report generation failed.");
    } finally {
      setReportLoading(false);
    }
  };

  const totalScans = history.length;
  const safeScans = history.filter((item) => item.prediction === "good").length;
  const threatScans = history.filter((item) => item.prediction === "bad").length;
  const criticalScans = history.filter(
    (item) => item.risk_level === "CRITICAL"
  ).length;

  const colors = {
    good: "#16a34a",
    bad: "#dc2626",
    LOW: "#16a34a",
    MEDIUM: "#eab308",
    HIGH: "#f97316",
    CRITICAL: "#dc2626",
  };

  const cardStyle = {
    background: "#1e293b",
    padding: "22px",
    borderRadius: "14px",
    flex: "1 1 180px",
    textAlign: "center",
    border: "1px solid #334155",
  };

  const formatScore = (score) => `${Number(score ?? 0).toFixed(2)}%`;

  return (
    <div style={{
      minHeight: "100vh",
      background: "#0f172a",
      color: "#f8fafc",
      padding: "30px 5%",
      fontFamily: "Arial, sans-serif",
      boxSizing: "border-box"
    }}>
      <header style={{ textAlign: "center", marginBottom: "35px" }}>
        <h1 style={{ fontSize: "clamp(30px, 5vw, 46px)", marginBottom: "10px" }}>
          🛡️ PhishGuard AI
        </h1>
        <p style={{ color: "#94a3b8", fontSize: "16px" }}>
          AI-Powered Phishing URL Detection Platform
        </p>
      </header>

      <section style={{
        display: "flex",
        gap: "18px",
        flexWrap: "wrap",
        marginBottom: "35px"
      }}>
        <div style={cardStyle}>
          <p style={{ color: "#94a3b8" }}>Total Scans</p>
          <h1>{totalScans}</h1>
        </div>
        <div style={cardStyle}>
          <p style={{ color: "#4ade80" }}>AI Classified Safe</p>
          <h1>{safeScans}</h1>
        </div>
        <div style={cardStyle}>
          <p style={{ color: "#f87171" }}>AI Detected Threats</p>
          <h1>{threatScans}</h1>
        </div>
        <div style={cardStyle}>
          <p style={{ color: "#fca5a5" }}>Critical Heuristic Risk</p>
          <h1>{criticalScans}</h1>
        </div>
      </section>

      <main style={{
        maxWidth: "950px",
        margin: "auto",
        background: "#1e293b",
        border: "1px solid #334155",
        borderRadius: "18px",
        padding: "clamp(18px, 4vw, 32px)"
      }}>
        <h2 style={{ marginTop: 0 }}>🔍 Scan a URL</h2>
        <p style={{ color: "#94a3b8", fontSize: "14px" }}>
          Enter a website address to analyze its phishing characteristics.
        </p>

        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !loading) checkPhishing();
          }}
          placeholder="https://example.com"
          aria-label="URL to scan"
          style={{
            width: "100%",
            boxSizing: "border-box",
            padding: "16px",
            borderRadius: "9px",
            border: "1px solid #475569",
            background: "#0f172a",
            color: "white",
            fontSize: "15px",
            marginBottom: "14px"
          }}
        />

        <button
          onClick={checkPhishing}
          disabled={loading}
          style={{
            width: "100%",
            padding: "15px",
            borderRadius: "9px",
            border: "none",
            background: loading ? "#475569" : "#2563eb",
            color: "white",
            fontWeight: "bold",
            fontSize: "16px",
            cursor: loading ? "not-allowed" : "pointer"
          }}
        >
          {loading ? "Analyzing URL..." : "Scan URL"}
        </button>

        {error && (
          <p role="alert" style={{
            background: "#7f1d1d",
            color: "#fecaca",
            padding: "12px",
            borderRadius: "8px",
            marginTop: "18px"
          }}>
            {error}
          </p>
        )}

        {result && (
          <section style={{
            marginTop: "28px",
            padding: "24px",
            borderRadius: "14px",
            background: "#111827",
            border: "1px solid #334155"
          }}>
            <h2 style={{ marginTop: 0 }}>Threat Analysis</h2>

            <p style={{ color: "#94a3b8", overflowWrap: "anywhere" }}>
              Scanned URL: {result.url}
            </p>

            <div style={{
              padding: "17px",
              borderRadius: "10px",
              background: result.prediction === "bad" ? "#450a0a" : "#052e16",
              marginBottom: "20px"
            }}>
              <p style={{ color: "#cbd5e1", margin: "0 0 8px" }}>
                AI Classification
              </p>
              <h2 style={{
                color: colors[result.prediction],
                margin: 0,
                fontSize: "25px"
              }}>
                {result.prediction === "bad" ? "⚠️ SUSPICIOUS" : "✓ SAFE"}
              </h2>
              <p style={{ color: "#cbd5e1", fontSize: "13px", marginBottom: 0 }}>
                Model classification threshold: {Number(result.classification_threshold * 100).toFixed(0)}%
              </p>
            </div>

            <div style={{ marginBottom: "22px" }}>
              <div style={{
                display: "flex",
                justifyContent: "space-between",
                gap: "10px",
                flexWrap: "wrap"
              }}>
                <strong>ML Phishing Score</strong>
                <strong style={{
                  color: result.prediction === "bad" ? "#f87171" : "#4ade80"
                }}>
                  {formatScore(result.ml_phishing_score)}
                </strong>
              </div>
              <div style={{
                height: "13px",
                background: "#374151",
                borderRadius: "10px",
                overflow: "hidden",
                marginTop: "10px"
              }}>
                <div style={{
                  width: `${Math.min(100, Math.max(0, Number(result.ml_phishing_score || 0)))}%`,
                  height: "100%",
                  background: result.prediction === "bad" ? "#dc2626" : "#16a34a",
                  borderRadius: "10px"
                }} />
              </div>
              <p style={{ color: "#94a3b8", fontSize: "12px" }}>
                Model-derived score; not a calibrated real-world probability.
              </p>
            </div>

            <div style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "15px",
              marginBottom: "20px"
            }}>
              <div style={{
                flex: "1 1 180px",
                background: "#1e293b",
                padding: "16px",
                borderRadius: "10px"
              }}>
                <p style={{ color: "#94a3b8", marginTop: 0 }}>
                  Heuristic Risk Score
                </p>
                <h2 style={{ marginBottom: 0 }}>{result.risk_score}/100</h2>
              </div>

              <div style={{
                flex: "1 1 180px",
                background: "#1e293b",
                padding: "16px",
                borderRadius: "10px"
              }}>
                <p style={{ color: "#94a3b8", marginTop: 0 }}>
                  Heuristic Risk Level
                </p>
                <h2 style={{
                  color: colors[result.risk_level] || "#f8fafc",
                  marginBottom: 0
                }}>
                  {result.risk_level}
                </h2>
              </div>
            </div>

            <h3>Security Indicators</h3>
            {result.reasons?.length > 0 ? (
              <ul>
                {result.reasons.map((reason, index) => (
                  <li key={index} style={{ marginBottom: "7px" }}>{reason}</li>
                ))}
              </ul>
            ) : (
              <p style={{ color: "#94a3b8" }}>
                No heuristic warning indicators detected.
              </p>
            )}

            {result.database_saved === false && (
              <p style={{
                color: "#fbbf24",
                background: "#422006",
                padding: "12px",
                borderRadius: "8px"
              }}>
                ⚠️ This scan is currently stored in temporary memory, not MongoDB.
              </p>
            )}
          </section>
        )}

        <button
          onClick={downloadReport}
          disabled={reportLoading}
          style={{
            width: "100%",
            marginTop: "18px",
            padding: "13px",
            borderRadius: "9px",
            border: "1px solid #475569",
            background: "#334155",
            color: "white",
            fontWeight: "bold",
            cursor: reportLoading ? "not-allowed" : "pointer"
          }}
        >
          {reportLoading ? "Generating PDF..." : "📄 Download Latest Scan Report"}
        </button>
      </main>

      <section style={{ maxWidth: "1100px", margin: "40px auto" }}>
        <h2>📋 Recent Scan Activity</h2>
        <div style={{ overflowX: "auto", borderRadius: "12px" }}>
          <table style={{
            width: "100%",
            borderCollapse: "collapse",
            background: "#1e293b",
            minWidth: "650px"
          }}>
            <thead>
              <tr style={{ background: "#334155", textAlign: "left" }}>
                {["URL", "AI Classification", "ML Score", "Heuristic Risk", "Risk Score"].map((heading) => (
                  <th key={heading} style={{ padding: "15px" }}>{heading}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{
                    padding: "22px",
                    textAlign: "center",
                    color: "#94a3b8"
                  }}>
                    No scans recorded yet.
                  </td>
                </tr>
              ) : (
                history.map((item, index) => (
                  <tr key={`${item.timestamp || item.url}-${index}`} style={{
                    borderBottom: "1px solid #334155"
                  }}>
                    <td style={{
                      padding: "14px",
                      maxWidth: "280px",
                      overflowWrap: "anywhere"
                    }}>
                      {item.url}
                    </td>
                    <td style={{
                      padding: "14px",
                      color: colors[item.prediction]
                    }}>
                      {item.prediction === "bad" ? "SUSPICIOUS" : "SAFE"}
                    </td>
                    <td style={{ padding: "14px" }}>
                      {formatScore(item.ml_phishing_score)}
                    </td>
                    <td style={{
                      padding: "14px",
                      color: colors[item.risk_level]
                    }}>
                      {item.risk_level}
                    </td>
                    <td style={{ padding: "14px" }}>
                      {item.risk_score}/100
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <footer style={{
        textAlign: "center",
        color: "#64748b",
        fontSize: "12px",
        padding: "20px"
      }}>
        PhishGuard AI • Machine Learning + Heuristic URL Analysis
      </footer>
    </div>
  );
}

export default App;
