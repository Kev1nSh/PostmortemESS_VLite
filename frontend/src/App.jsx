import { useState, useEffect } from "react";
import "./App.css";
import Statistics from "./components/statistics";
import SecurityTips from "./components/security-tips";

function App() {
  const isStatisticsPage = window.location.pathname === "/statistics";

  // Use the OS theme
  const [systemDarkMode, setSystemDarkMode] = useState(() => {
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  const [themePreference, setThemePreference] = useState(() => {
    const savedTheme = localStorage.getItem("postmortem-darkmode");
    return ["system", "light", "dark"].includes(savedTheme)
      ? savedTheme
      : "system";
  });

  const darkMode =
    themePreference === "system"
      ? systemDarkMode
      : themePreference === "dark";

  const handleThemePreferenceChange = (theme) => {
    localStorage.setItem("postmortem-darkmode", theme);
    setThemePreference(theme);
  };

  useEffect(() => {
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");

    const handleChange = (event) => {
      setSystemDarkMode(event.matches);
    };

    mediaQuery.addEventListener("change", handleChange);

    return () => {
      mediaQuery.removeEventListener("change", handleChange);
    };
  }, []);

  return (
    <div className={`theme-root ${darkMode ? "dark-mode" : "light-mode"}`}>
      {isStatisticsPage ? (
        <Statistics darkMode={darkMode} />
      ) : (
        <HomePage
          darkMode={darkMode}
          onThemeChange={handleThemePreferenceChange}
          themePreference={themePreference}
        />
      )}
    </div>
  );
}

function HomePage({ darkMode, themePreference, onThemeChange }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expandedView, setExpandedView] = useState(null);
  const [openInstructions, setOpenInstructions] = useState(null);

  const handleFileChange = (event) => {
    const file = event.target.files?.[0];

    if (!file) {
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
    setResult(null);
    setError(null);
    setExpandedView(null);
  };

  const handleAnalyze = async () => {
    if (!selectedFile) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setExpandedView(null);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      console.error("Analyze error:", err);
      setError(`Analysis failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const toggleInstructions = (type) => {
    setOpenInstructions((current) =>
      current === type ? null : type
    );
  };

  return (
    <main className={`app ${darkMode ? "dark-mode" : "light-mode"}`}>
      <div className="app-container">

        <div className="theme-toggle">
          <div className="button-group">
            <button
              type="button"
              className={
                themePreference === "system"
                  ? "theme-button active"
                  : "theme-button"
              }
              onClick={() => onThemeChange("system")}
            >
              System
            </button>

            <button
              type="button"
              className={
                themePreference === "light"
                  ? "theme-button active"
                  : "theme-button"
              }
              onClick={() => onThemeChange("light")}
            >
              Light
            </button>

            <button
              type="button"
              className={
                themePreference === "dark"
                  ? "theme-button active"
                  : "theme-button"
              }
              onClick={() => onThemeChange("dark")}
            >
              Dark
            </button>
          </div>
        </div>

        <h1>PostmortemESS</h1>

        <p>
          PostmortemESS är ett verktyg för att analysera misstänkta mejl.
        </p>

        {/* Email upload */}
        <div className="card">
          <div className="card-content">

            <div className="upload-area">
              <input
                id="email-upload"
                type="file"
                accept=".eml,.msg,message/rfc822"
                onChange={handleFileChange}
              />

              <label htmlFor="email-upload">
                Ladda upp en .eml eller .msg fil för analys
              </label>

              {selectedFile && (
                <p>
                  Vald fil: <strong>{selectedFile.name}</strong>
                </p>
              )}
            </div>

            <button
              type="button"
              className="action-button"
              disabled={!selectedFile || loading}
              onClick={handleAnalyze}
            >
              <strong>
                {loading ? "Analyserar..." : "Analysera mail"}
              </strong>
            </button>

            {error && <p className="error-message">{error}</p>}

            {result && (
              <div className="result-layout">

                {/* Left box Analysresultat */}
                <div className="result">
                  <h3>Analysresultat</h3>

                  <p>
                    <span className="result-verdict">
                      <strong>Verdict:</strong> {result.verdict}
                    </span>
                  </p>

                  <p>
                    <strong>Report ID:</strong> {result.report_id}
                  </p>

                  <p>
                    <strong>Domain:</strong>{" "}
                    {result.domain || "Okänd"}
                  </p>

                  {/* Button 1 anledningar */}
                  <p>
                    <button
                      type="button"
                      className="action-button"
                      onClick={() =>
                        setExpandedView(
                          expandedView === "reasons"
                            ? null
                            : "reasons",
                        )
                      }
                    >
                      {expandedView === "reasons"
                        ? "Dölj anledningarna"
                        : "Visa varför detta beslut?"}
                    </button>
                  </p>

                  {/* Button 2 JSON */}
                  <p>
                    <button
                      type="button"
                      className="action-button"
                      onClick={() =>
                        setExpandedView(
                          expandedView === "json"
                            ? null
                            : "json",
                        )
                      }
                    >
                      {expandedView === "json"
                        ? "Dölj JSON-rapport"
                        : "Visa fullständig JSON-rapport"}
                    </button>
                  </p>
                </div>

                {/* Right box Security tips */}
                <SecurityTips />

                {/* Expandview under resultatkortet */}
                {expandedView && (
                  <div className="expanded-result">

                    {/* ANLEDNINGAR */}
                    {expandedView === "reasons" && (
                      <div className="verdict-reasons">
                        <h3>Varför detta beslut?</h3>

                        {result.verdict_explanation ? (
                          <p className="verdict-explanation">
                            {result.verdict_explanation}
                          </p>
                        ) : (
                          <p className="verdict-empty">
                            Ingen sammanfattande beslutsförklaring finns
                            tillgänglig.
                          </p>
                        )}

                        {result.reason_summary && (
                          <p className="reason-summary">
                            {result.reason_summary}
                          </p>
                        )}

                        {Array.isArray(result.reason_details) &&
                        result.reason_details.length > 0 ? (
                          <div className="reason-list">
                            {result.reason_details.map((reason, index) => (
                              <div
                                className={`reason-item severity-${
                                  reason.severity || "info"
                                }`}
                                key={`${reason.title || "reason"}-${index}`}
                              >
                                <div className="reason-heading">
                                  <strong>
                                    {reason.title || "Analysfynd"}
                                  </strong>

                                  <span className="severity-label">
                                    {reason.severity === "high"
                                      ? "Hög"
                                      : reason.severity === "medium"
                                        ? "Medel"
                                        : "Info"}
                                  </span>
                                </div>

                                {reason.description && (
                                  <p>{reason.description}</p>
                                )}
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="verdict-empty">
                            Inga detaljerade beslutsanledningar finns
                            tillgängliga.
                          </p>
                        )}
                      </div>
                    )}

                    {/* Full JSON report */}
                    {expandedView === "json" && (
                      <div className="json-result">
                        <pre>
                          {JSON.stringify(result, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Instructions / systemöversikt */}
        <div className="card">
          <div className="card-content">

            <h3>
              <strong>Hur fungerar analysen?</strong>
            </h3>

            <p>
              <strong>Ladda ner</strong> originalmejlet som en{" "}
              <strong>.eml</strong>-fil eller <strong>.msg</strong>-fil och
              ladda upp det här. PostmortemESS analyserar mejlets innehåll och
              visar en rapport med information om dess säkerhet.
            </p>

            <h3>
              <strong>
                Nyfiken på hur PostmortemESS som system fungerar i djupet?{" "}
              </strong>
            </h3>

            <p>
              Systemöversikten visar hur PostmortemESS tar emot, analyserar och
              rapporterar misstänkta mejl.
            </p>

            <p>
              Klicka på knappen nedan för att visa PostmortemESS systemöversikt.
            </p>

            <div className="systemo-oversikt">
              <div
                className={`systemo-card ${
                  openInstructions === "systemo" ? "is-open" : ""
                }`}
              >
                <button
                  type="button"
                  className="systemo-button"
                  onClick={() => toggleInstructions("systemo")}
                >
                  {openInstructions === "systemo"
                    ? "Dölj systemöversikt"
                    : "Visa systemöversikt"}
                </button>

                {openInstructions === "systemo" && (
                  <div className="systemo-section">
                    <h3>
                      <strong>Systemöversikt</strong>
                    </h3>

                    <p className="systemo-text">
                      Systemet består av flera komponenter som arbetar
                      tillsammans för att ge användaren en snabb och pålitlig
                      analys. Kortfattat hur systemet fungerar:
                    </p>

                    <p className="systemo-text">
                      1. Användaren laddar upp en mejl i sin prefererade format,
                      som t.ex i <strong>.eml</strong> eller{" "}
                      <strong>.msg</strong> format.
                    </p>

                    <p className="systemo-text">
                      2. PostmortemESS parserar, extraherar och kontrollerar
                      information från den uppladdade filen.
                    </p>

                    <p className="systemo-text">
                      3. PostmortemESS skannar med externa källor för att hitta
                      kända hot och virus.
                    </p>

                    <p className="systemo-text">
                      4. Resultatet av analysen presenteras i en rapport som
                      visar information om mejlens säkerhet.
                    </p>

                    <p className="systemo-text">
                      Se bilden nedan för en visuell representation av systemets
                      arkitektur.
                    </p>

                    <img
                      src="/systemo1.png"
                      alt="Systemöversikt för PostmortemESS"
                      className="instruction-image"
                    />
                  </div>
                )}
              </div>
            </div>

            <p>
              <strong>Osäker på hur man sparar ett mejl?</strong> Se
              instruktionerna nedan.
            </p>

            <h3>
              <strong>Hur sparar man ett mejl som .msg /.eml-fil:</strong>
            </h3>

            <p>
              Instruktioner för att spara ett mejl som en{" "}
              <strong>.eml</strong> eller <strong>.msg</strong>-fil finns
              nedan för Outlook.
            </p>

            <p>
              <strong>Klicka</strong> på din e-postklient nedan för att visa
              instruktionerna.
            </p>

            {/* Msg and Eml */}
            <div className="instruction-grid">

              <div
                className={`instruction-card ${
                  openInstructions === "eml" ? "is-open" : ""
                }`}
              >
                <button
                  type="button"
                  className="instruction-button"
                  onClick={() => toggleInstructions("eml")}
                >
                  {openInstructions === "eml"
                    ? "Dölj instruktioner för .eml-fil"
                    : "Visa instruktioner för .eml-fil"}
                </button>

                {openInstructions === "eml" && (
                  <div className="instruction-section">
                    <h3>Instruktioner för .eml-fil</h3>

                    <p className="instruction-text">
                      Det finns två sätt att ladda ner ett mejl som en{" "}
                      <strong>.eml</strong>-fil i Outlook.
                    </p>

                    <p className="instruction-text">
                      <strong>Alternativ 1:</strong> Markera det misstänkta
                      mejlet och
                      <strong> högerklicka</strong> på det. Välj{" "}
                      <strong>Ladda ned → Ladda ned som EML</strong>.
                    </p>

                    <img
                      src="/eml1.png"
                      alt="Outlook: högerklicka på mejlet och välj Ladda ned som EML"
                      className="instruction-image"
                    />

                    <p className="instruction-text">
                      <strong>Alternativ 2:</strong> Öppna mejlet du vill
                      analysera. Klicka på de tre punkterna{" "}
                      <strong>(...)</strong> och välj{" "}
                      <strong>Ladda ned → Ladda ned som EML</strong>.
                    </p>

                    <img
                      src="/eml2.png"
                      alt="Outlook: öppna menyn och välj Ladda ned som EML"
                      className="instruction-image"
                    />

                    <p className="instruction-text">
                      <strong>Spara</strong> filen på datorn och ladda sedan upp{" "}
                      <strong>.eml</strong>-filen på denna sida för analys.
                    </p>

                    <img
                      src="/eml3.png"
                      alt="Spara .eml-filen på datorn"
                      className="instruction-image"
                    />
                  </div>
                )}
              </div>

              <div
                className={`instruction-card ${
                  openInstructions === "msg" ? "is-open" : ""
                }`}
              >
                <button
                  type="button"
                  className="instruction-button"
                  onClick={() => toggleInstructions("msg")}
                >
                  {openInstructions === "msg"
                    ? "Dölj instruktioner för .msg-fil"
                    : "Visa instruktioner för .msg-fil"}
                </button>

                {openInstructions === "msg" && (
                  <div className="instruction-section">
                    <h3>Instruktioner för .msg-fil</h3>

                    <p className="instruction-text">
                      <strong>Alternativ 1:</strong> Markera det misstänkta
                      mejlet och
                      <strong> högerklicka</strong> på det. Välj{" "}
                      <strong>Ladda ned → Ladda ned som MSG</strong>.
                    </p>

                    <img
                      src="/msg1.png"
                      alt="Outlook: välj Ladda ned meddelande"
                      className="instruction-image"
                    />

                    <p className="instruction-text">
                      <strong>Alternativ 2:</strong> Öppna mejlet du vill
                      analysera. Klicka på de tre punkterna{" "}
                      <strong>(...)</strong> och välj{" "}
                      <strong>Ladda ned → Ladda ned som MSG</strong>.
                    </p>

                    <img
                      src="/msg2.png"
                      alt="Outlok: välj Ladda ned meddelande"
                      className="instruction-image"
                    />

                    <p className="instruction-text">
                      <strong>Spara</strong> filen på datorn och ladda sedan upp{" "}
                      <strong>.msg</strong>-filen på denna sida för analys.
                    </p>

                    <img
                      src="/msg3.png"
                      alt="Spara .msg-filen på datorn"
                      className="instruction-image"
                    />
                  </div>
                )}
              </div>
            </div>

            <p className="instruction-text">
              <strong>Viktigt:</strong> Ladda upp originalmejlet som en{" "}
              <strong>.eml</strong>-fil eller en <strong>.msg</strong>-fil.
              Ladda inte upp skärmdumpar eller konverterade dokument.
            </p>

          </div>
        </div>

      </div>
    </main>
  );
}

export default App;