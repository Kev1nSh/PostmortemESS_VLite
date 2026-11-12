import { useEffect, useState } from "react";
import Plot from "react-plotly.js";
import "./statistics.css";

const VERDICTS = {
  safe: "MOST LIKELY SAFE",
  unsafe: "MOST LIKELY UNSAFE",
  further: "FURTHER ANALYSIS REQUIRED",
};

function Statistics({ darkMode }) {
  const [period, setPeriod] = useState("30d");

  const [verdicts, setVerdicts] = useState([]);
  const [analyses, setAnalyses] = useState([]);
  const [domains, setDomains] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [reports, setReports] = useState([]);
  const [reportLoading, setReportLoading] = useState(true);
  const [reportError, setReportError] = useState(null);

  useEffect(() => {
    loadReports();
  }, []);

  useEffect(() => {
    loadStatistics();
  }, [period]);

  const loadReports = async () => {
    setReportLoading(true);
    setReportError(null);

    try {
      const response = await fetch("/api/reports?limit=20");

      if (!response.ok) {
        throw new Error(`Reports API request failed: ${response.status}`);
      }

      const data = await response.json();

      setReports(data);
    } catch (err) {
      console.error("Reports error:", err);
      setReportError(`Failed to load reports: ${err.message}`);
    } finally {
      setReportLoading(false);
    }
  };

  const loadStatistics = async () => {
    setLoading(true);
    setError(null);

    try {
      const [verdictResponse, analysesResponse, domainsResponse] =
        await Promise.all([
          fetch(`/api/stats/verdicts?period=${period}`),
          fetch(`/api/stats/analyses?period=${period}`),
          fetch(`/api/stats/domains?period=${period}`),
        ]);

      if (!verdictResponse.ok) {
        throw new Error(
          `Verdict API request failed: ${verdictResponse.status}`,
        );
      }

      if (!analysesResponse.ok) {
        throw new Error(
          `Analysis API request failed: ${analysesResponse.status}`,
        );
      }

      if (!domainsResponse.ok) {
        throw new Error(
          `Domain API request failed: ${domainsResponse.status}`,
        );
      }

      const verdictData = await verdictResponse.json();
      const analysisData = await analysesResponse.json();
      const domainData = await domainsResponse.json();

      setVerdicts(verdictData);
      setAnalyses(analysisData);
      setDomains(domainData);
    } catch (err) {
      console.error("Statistics error:", err);
      setError(`Failed to load statistics: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const getVerdictCount = (verdict) => {
    const item = verdicts.find((entry) => entry.verdict === verdict);

    return item?.count ?? 0;
  };

  const safeCount = getVerdictCount(VERDICTS.safe);
  const unsafeCount = getVerdictCount(VERDICTS.unsafe);
  const furtherCount = getVerdictCount(VERDICTS.further);

  const totalCount = safeCount + unsafeCount + furtherCount;

  const chartTheme = {
    paper_bgcolor: darkMode ? "#121820" : "#ffffff",
    plot_bgcolor: darkMode ? "#121820" : "#ffffff",

    font: {
      color: darkMode ? "#edf2f7" : "#1e293b",
      family: "system-ui, sans-serif",
    },

    xaxis: {
      color: darkMode ? "#edf2f7" : "#1e293b",
      gridcolor: darkMode ? "#394858" : "#e5e7eb",
      zerolinecolor: darkMode ? "#526171" : "#cbd5e1",
    },

    yaxis: {
      color: darkMode ? "#edf2f7" : "#1e293b",
      gridcolor: darkMode ? "#394858" : "#e5e7eb",
      zerolinecolor: darkMode ? "#526171" : "#cbd5e1",
    },
  };

  return (
    <main className="statistics">
      <div className="statistics-container">
        <div className="statistics-header">
          <div>
            <h1>Reports data</h1>

            <p>
              Overview of email analyses performed by PostmortemESS.
            </p>
          </div>

          <select
            value={period}
            onChange={(event) => setPeriod(event.target.value)}
            className="period-selector"
          >
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
            <option value="all">All time</option>
          </select>
        </div>

        {loading && (
          <p className="loading-message">
            Loading application statistics...
          </p>
        )}

        {error && (
          <p className="error-message">
            {error}
          </p>
        )}

        {!loading && !error && (
          <>
            <div className="statistics-cards">
              <div className="stat-card">
                <h3>Total Analyses</h3>
                <div className="stat-number">
                  {totalCount}
                </div>
              </div>

              <div className="stat-card">
                <h3>Unsafe mails</h3>
                <div className="stat-number">
                  {unsafeCount}
                </div>
              </div>

              <div className="stat-card">
                <h3>Mails Needing Further Analysis</h3>
                <div className="stat-number">
                  {furtherCount}
                </div>
              </div>

              <div className="stat-card">
                <h3>Safe mails</h3>
                <div className="stat-number">
                  {safeCount}
                </div>
              </div>
            </div>

            <div className="statistics-card">
              <h3>Analyses Over Time</h3>

              <Plot
                data={[
                  {
                    x: analyses.map((item) => item.day),
                    y: analyses.map((item) => item.count),
                    type: "scatter",
                    mode: "lines+markers",
                  },
                ]}
                layout={{
                  ...chartTheme,
                  autosize: true,
                  margin: {
                    l: 50,
                    r: 20,
                    t: 20,
                    b: 50,
                  },
                  xaxis: {
                    ...chartTheme.xaxis,
                    title: "Date",
                  },
                  yaxis: {
                    ...chartTheme.yaxis,
                    title: "Analyses",
                  },
                }}
                useResizeHandler
                style={{
                  width: "100%",
                  height: "400px",
                }}
                config={{
                  responsive: true,
                  displayModeBar: false,
                }}
              />
            </div>

            <div className="statistics-card">
              <h3>Top Reported Domains</h3>

              <Plot
                data={[
                  {
                    x: domains.map((item) => item.count),
                    y: domains.map((item) => item.domain),
                    type: "bar",
                    orientation: "h",
                  },
                ]}
                layout={{
                  ...chartTheme,
                  autosize: true,
                  margin: {
                    l: 180,
                    r: 20,
                    t: 20,
                    b: 50,
                  },
                  xaxis: {
                    ...chartTheme.xaxis,
                    title: "Reports",
                  },
                  yaxis: {
                    ...chartTheme.yaxis,
                    title: "Domain",
                  },
                }}
                useResizeHandler
                style={{
                  width: "100%",
                  height: "450px",
                }}
                config={{
                  responsive: true,
                  displayModeBar: false,
                }}
              />
            </div>

            <div className="statistics-card">
              <h3>Reported emails</h3>

              {reportLoading && (
                <p className="loading-message">
                  Loading reports...
                </p>
              )}

              {reportError && (
                <p className="error-message">
                  {reportError}
                </p>
              )}

              {!reportLoading &&
                !reportError &&
                reports.length === 0 && (
                  <p>
                    No reported emails in the last 30 days.
                  </p>
                )}

              {!reportLoading &&
                !reportError &&
                reports.length > 0 && (
                  <div className="reports-list">
                    {reports.map((report) => (
                      <div
                        key={report.report_id}
                        className="report-card"
                      >
                        <h3>{report.verdict}</h3>

                        <p>
                          <strong>Sender:</strong>{" "}
                          {report.sender_address || "Unknown"}
                        </p>

                        <p>
                          <strong>Domain:</strong>{" "}
                          {report.sender_domain || "Unknown"}
                        </p>

                        <p>
                          <strong>Reported:</strong>{" "}
                          {report.created_at}
                        </p>

                        <p>
                          <strong>Report ID:</strong>{" "}
                          {report.report_id}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
            </div>
          </>
        )}
      </div>
    </main>
  );
}

export default Statistics;