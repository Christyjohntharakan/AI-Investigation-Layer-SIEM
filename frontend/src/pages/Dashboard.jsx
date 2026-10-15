import { useEffect, useMemo, useState } from "react";
import {
  FaShieldAlt,
  FaBell,
  FaBug,
  FaRobot,
  FaCog,
  FaSearch,
  FaSyncAlt,
  FaExclamationTriangle,
  FaServer,
  FaClock,
  FaChevronRight,
  FaCrosshairs,
  FaBrain,
  FaNetworkWired,
} from "react-icons/fa";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";


import API from "../services/api";
import "../styles/dashboard.css";

export default function Dashboard() {
 const [logs, setLogs] = useState([]);
 const [incidents, setIncidents] = useState([]);
 const [anomalies, setAnomalies] = useState({
  summary: {
    behavioral_count: 0,
    ml_anomalous_windows: 0,
    ml_total_windows: 0,
  },
  behavioral_anomalies: [],
  isolation_forest_anomalies: [],
});
const [selectedIncident, setSelectedIncident] = useState(null);

  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [lastUpdated, setLastUpdated] = useState(null);

  async function loadDashboard() {
    try {
      const [
        logsResponse,
        incidentsResponse,
        anomaliesResponse,
      ] = await Promise.all([
        API.get("/logs"),
        API.get("/incidents"),
        API.get("/anomalies"),
      ]);

      const logData = Array.isArray(logsResponse.data)
        ? logsResponse.data
        : [];

      const incidentData = Array.isArray(incidentsResponse.data)
        ? incidentsResponse.data
        : [];

      setLogs(logData);
      setIncidents(incidentData);
      setAnomalies(
        anomaliesResponse.data || {
          summary: {
            behavioral_count: 0,
            ml_anomalous_windows: 0,
            ml_total_windows: 0,
          },
          behavioral_anomalies: [],
          isolation_forest_anomalies: [],
        }
      );
      setConnected(true);
      setLastUpdated(new Date());
    } catch (error) {
      console.error("Dashboard API error:", error);
      setConnected(false);
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    let isMounted = true;
    let isFetching = false;

    const refreshDashboard = async () => {
        if (!isMounted || isFetching) return;

        isFetching = true;

        try {
            await loadDashboard();
        } finally {
            isFetching = false;
        }
    };

    refreshDashboard();

    const interval = setInterval(refreshDashboard, 15000);

    return () => {
        isMounted = false;
        clearInterval(interval);
    };
}, []);


  

  const getRisk = (incident) =>
    incident?.risk?.score ??
    incident?.max_risk_score ??
    incident?.risk_score ??
    0;

  const getPriority = (incident) =>
  (
    incident?.risk?.priority ??
    incident?.priority ??
    "low"
  ).toLowerCase();

  const highRisk = incidents.filter(
    (incident) => getPriority(incident) === "high" ||
      getPriority(incident) === "critical" ||
      getRisk(incident) >= 70
  );

  const mediumRisk = incidents.filter(
    (incident) =>
      getPriority(incident) === "medium" ||
      (getRisk(incident) >= 40 && getRisk(incident) < 70)
  );

  const lowRisk = incidents.filter(
    (incident) =>
      getPriority(incident) === "low" ||
      getRisk(incident) < 40
  );




  const mlAnomalies = (
  anomalies.isolation_forest_anomalies || []
).filter((item) => item.is_anomaly);

  const behavioralAnomalies =
  anomalies.behavioral_anomalies || [];

  const averageRisk =
    incidents.length > 0
      ? Math.round(
          incidents.reduce(
            (sum, incident) => sum + getRisk(incident),
            0
          ) / incidents.length
        )
      : 0;

  const agents = useMemo(() => {
    const map = {};

    logs.forEach((log) => {
      const name =
        log.agent_name ||
        log.agent ||
        "Unknown agent";

      if (!map[name]) {
        map[name] = {
          name,
          ip: log.agent_ip || "—",
          events: 0,
        };
      }

      map[name].events++;
    });

    return Object.values(map);
  }, [logs]);

  const mitreCounts = useMemo(() => {
    const counts = {};

    incidents.forEach((incident) => {
      const techniques =
        incident.mitre_techniques || [];

      techniques.forEach((technique) => {
        counts[technique] =
          (counts[technique] || 0) + 1;
      });
    });

    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [incidents]);

  const filteredIncidents = incidents.filter((incident) => {
    const priority = getPriority(incident);

    const matchesFilter =
      filter === "all" ||
      priority === filter;

    const text = [
      incident.incident_id,
      incident.agent_name,
      incident.category,
      ...(incident.mitre_techniques || []),
    ]
      .join(" ")
      .toLowerCase();

    return (
      matchesFilter &&
      text.includes(search.toLowerCase())
    );
  });
  const severityData = [
    {
      name: "Critical",
      value: incidents.filter((i) => getPriority(i) === "critical").length,
      color: "#ff4d5e",
    },
    {
      name: "High",
      value: incidents.filter((i) => getPriority(i) === "high").length,
      color: "#ff963d",
    },
    {
      name: "Medium",
      value: incidents.filter((i) => getPriority(i) === "medium").length,
      color: "#f2ca52",
    },
    {
      name: "Low",
      value: incidents.filter((i) => getPriority(i) === "low").length,
      color: "#43c995",
    },
  ];

  function openIncident(incident) {
    setSelectedIncident(incident);
  }

  return (
    <div className="soc-shell">

     
{/* SIDEBAR */}
      <aside className="soc-sidebar">

        <div className="brand">
          <div className="brand-icon">
            <FaShieldAlt />
          </div>

          <div>
            <strong>AI SOC</strong>
            <span>Investigation Layer</span>
          </div>
        </div>

    <nav>
          <a className="nav-item active" href="#overview">
            <FaShieldAlt />
            Dashboard
          </a>

          <a className="nav-item" href="#incidents">
            <FaBell />
            Incidents
            <span className="nav-count">
              {incidents.length}
            </span>
          </a>

          <a className="nav-item" href="#anomalies">
  <FaBrain />
  Anomalies
  <span className="nav-count">
    {mlAnomalies.length}
  </span>
</a>

          <a className="nav-item" href="#mitre">
            <FaBug />
            MITRE ATT&CK
          </a>

          <a className="nav-item" href="#investigation">
            <FaRobot />
            Investigation
          </a>

          <a className="nav-item" href="#agents">
            <FaServer />
            Endpoints
          </a>

        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className={connected ? "status-dot online" : "status-dot"} />
            <div>
              <strong>
                {connected ? "Backend connected" : "Backend offline"}
              </strong>
              <small>FastAPI · Wazuh</small>
            </div>
          </div>

          <a className="nav-item">
            <FaCog />
            Settings
          </a>
        </div>
      </aside>

      {/* MAIN */}

      <main className="soc-main">

        {/* TOP BAR */}

        <header className="topbar">

          <div>
            <div className="eyebrow">
              SECURITY OPERATIONS CENTER
            </div>

            <h1>
              Investigation Overview
            </h1>

            <p>
              Real-time security monitoring, incident correlation
              and investigation intelligence.
            </p>
          </div>

          <div className="top-actions">

            <div className="live-indicator">
              <span />
              LIVE
            </div>

            <button
              className="refresh-btn"
              onClick={loadDashboard}
            >
              <FaSyncAlt />
            </button>

          </div>

        </header>

        <div className="connection-line">

          <span className={connected ? "status-dot online" : "status-dot"} />

          {connected
            ? "Backend connected"
            : "Backend connection failed"}

          {lastUpdated && (
            <span>
              Updated {lastUpdated.toLocaleTimeString()}
            </span>
          )}

        </div>

        {/* STAT CARDS */}

        <section id="overview" className="stat-grid">

          <StatCard
            label="Security Events"
            value={logs.length}
            description="Events analyzed"
            icon={<FaBell />}
            type="cyan"
          />

          <StatCard
            label="Active Incidents"
            value={incidents.length}
            description="Correlated incidents"
            icon={<FaCrosshairs />}
            type="purple"
          />

          <StatCard
            label="High Risk"
            value={highRisk.length}
            description="Requires attention"
            icon={<FaExclamationTriangle />}
            type="red"
          />

          <StatCard
            label="Agents"
            value={agents.length}
            description="Connected endpoints"
            icon={<FaServer />}
            type="green"
          />

          <StatCard
          label="Behavioral Anomalies"
          value={behavioralAnomalies.length}
          description="Rule-based anomalies"
          icon={<FaExclamationTriangle />}
          type="red"
          />
          
          <StatCard
          label="ML Anomalies"
          value={mlAnomalies.length}
          description="Isolation Forest"
          icon={<FaBrain />}
          type="purple"
          />

        </section>

        {/* ANALYTICS */}

        <section className="analytics-grid">

          <div className="panel risk-panel">


<PanelHeader
  eyebrow="RISK ANALYTICS"
  title="Incident Risk"
  count={incidents.length}
/>

<div className="risk-analytics-content">
  <div className="risk-breakdown">
    <RiskBar
      label="High"
      count={highRisk.length}
      total={incidents.length}
      type="high"
    />

    <RiskBar
      label="Medium"
      count={mediumRisk.length}
      total={incidents.length}
      type="medium"
    />

    <RiskBar
      label="Low"
      count={lowRisk.length}
      total={incidents.length}
      type="low"
    />

    <div className="risk-footer">
      <span>Average incident risk</span>
      <strong>{averageRisk}/100</strong>
    </div>
  </div>

  <div
    className={`risk-gauge ${
      averageRisk >= 80
        ? "risk-gauge-critical"
        : averageRisk >= 60
        ? "risk-gauge-high"
        : averageRisk >= 40
        ? "risk-gauge-medium"
        : "risk-gauge-low"
    }`}
    style={{
      "--risk": Math.max(
        0,
        Math.min(100, Number(averageRisk) || 0)
      )
    }}
    role="img"
    aria-label={`Average incident risk ${averageRisk} out of 100`}
  >
    <div className="risk-gauge-content">
      <strong className="risk-gauge-value">
        {Math.round(Number(averageRisk) || 0)}
      </strong>
      <span className="risk-gauge-label">/ 100 Risk</span>
    </div>
  </div>
</div>

<div className="severity-legend">
  <span><i className="legend-dot legend-high" /> High</span>
  <span><i className="legend-dot legend-medium" /> Medium</span>
  <span><i className="legend-dot legend-low" /> Low</span>
</div>
</div>


          <div
            className="panel"
            id="agents"
          >

            <PanelHeader
              eyebrow="ENDPOINTS"
              title="Agent Status"
              count={`${agents.length} detected`}
            />

            <div className="agent-list">

              {agents.length === 0 ? (
                <Empty text="No agents detected" />
              ) : (
                agents.map((agent) => (
                  <div
                    className="agent-row"
                    key={agent.name}
                  >
                    <span className="agent-live" />

                    <div className="agent-info">
                      <strong>{agent.name}</strong>
                      <small>{agent.ip}</small>
                    </div>

                    <div className="agent-events">
                      <strong>{agent.events}</strong>
                      <small>events</small>
                    </div>
                  </div>
                ))
              )}

            </div>

          </div>

        </section>

        {/* INCIDENT SEVERITY CHART */}
        <section className="panel severity-chart-panel">
          <PanelHeader
            eyebrow="THREAT DISTRIBUTION"
            title="Incident Severity Breakdown"
            count={`${incidents.length} incidents`}
          />

          <div className="severity-chart-layout">
            <div className="severity-donut">
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={75}
                    outerRadius={105}
                    paddingAngle={4}
                    stroke="none"
                  >
                    {severityData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  
                  <Tooltip
                    formatter={(value, name) => [
                      `${value} incidents`,
                      name,
                    ]}
                    contentStyle={{
                      backgroundColor: "#111c28",
                      border: "1px solid #34495e",
                      borderRadius: "8px",
                      color: "#ffffff",
                      padding: "10px 14px",
                    }}
                    itemStyle={{ color: "#ffffff" }}
                    labelStyle={{ color: "#9fb0c4" }}
                    wrapperStyle={{ zIndex: 10, pointerEvents: "none" }}
                  />
                </PieChart>
              </ResponsiveContainer>

              <div className="severity-donut-center">
                <strong>{incidents.length}</strong>
                <span>Total incidents</span>
              </div>
            </div>

            <div className="severity-chart-legend">
              {severityData.map((item) => (
                <div className="severity-chart-item" key={item.name}>
                  <span
                    className="severity-chart-dot"
                    style={{ background: item.color }}
                  />
                  <span>{item.name}</span>
                  <strong>{item.value}</strong>
                  <small>
                    {incidents.length
                      ? `${((item.value / incidents.length) * 100).toFixed(1)}%`
                      : "0%"}
                  </small>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ANOMALY DETECTION */}

<section className="panel anomaly-panel" id="anomalies">

  <PanelHeader
    eyebrow="AI ANOMALY DETECTION"
    title="Behavioral Anomalies"
    count={`${mlAnomalies.length} ML detected`}
  />

  <div className="anomaly-summary">

    <div className="anomaly-summary-item">
      <span>Rule-Based</span>
      <strong>{behavioralAnomalies.length}</strong>
    </div>

    <div className="anomaly-summary-item">
      <span>ML Detected</span>
      <strong>{mlAnomalies.length}</strong>
    </div>

    <div className="anomaly-summary-item">
      <span>Windows Analyzed</span>
      <strong>
        {anomalies.summary?.ml_total_windows ?? 0}
      </strong>
    </div>

  </div>

  {mlAnomalies.length === 0 ? (

    <Empty text="No ML anomalies detected." />

  ) : (

    <div className="anomaly-list">

      {mlAnomalies.map((anomaly, index) => (

        <div
          className="anomaly-card"
          key={index}
        >

          <div className="anomaly-card-header">

            <div>
              <span className="anomaly-label">
                ISOLATION FOREST
              </span>

              <h3>
                Behavioral anomaly detected
              </h3>
            </div>

            <span className="anomaly-score">
              {anomaly.decision_score}
            </span>

          </div>

          <div className="anomaly-details">

            <div>
              <span>Events</span>
              <strong>{anomaly.event_count}</strong>
            </div>

            <div>
              <span>First Seen</span>
              <strong>
                {formatDate(anomaly.first_seen)}
              </strong>
            </div>

            <div>
              <span>Last Seen</span>
              <strong>
                {formatDate(anomaly.last_seen)}
              </strong>
            </div>

          </div>

          <details className="anomaly-features">

            <summary>
              View behavioral features
            </summary>

            <div className="feature-grid">

              {Object.entries(
                anomaly.features || {}
              ).map(([name, value]) => (

                <div
                  className="feature-item"
                  key={name}
                >
                  <span>{name.replaceAll("_", " ")}</span>
                  <strong>{value}</strong>
                </div>

              ))}

            </div>

          </details>

          {/* SHAP EXPLANATION: Show which features influenced the ML score. */}
          <details className="anomaly-features shap-explanation">

            <summary>
              View SHAP explanation
            </summary>

            {anomaly.shap_explanation?.available ? (

              <>
                <p className="risk-summary">
                  {anomaly.shap_explanation.note}
                </p>
                                {/* KEY FINDING: Summarize the strongest features lowering the Isolation Forest score. */}
                <div className="risk-summary">
                  <strong>Key Finding</strong>

                  {(() => {
                    // Select the three strongest negative SHAP contributions.
                    const topContributors = (
                      anomaly.shap_explanation.feature_contributions || []
                    )
                      .filter((item) => Number(item.shap_value) < 0)
                      .sort((a, b) => a.shap_value - b.shap_value)
                      .slice(0, 3);

                    // Convert feature names into readable text for the analyst.
                    const featureNames = topContributors.map((item) =>
                      item.feature.replaceAll("_", " ")
                    );

                    // Avoid making a claim when no negative contributions exist.
                    if (featureNames.length === 0) {
                      return (
                        <p>
                          No features lowering the model score were identified
                          in the available SHAP results.
                        </p>
                      );
                    }

                    // Explain the model finding without claiming that an attack is confirmed.
                    return (
                      <p>
                        The strongest features lowering the model score are{" "}
                        {featureNames.join(", ")}. These contributions help
                        explain why the activity was flagged as anomalous;
                        they do not independently confirm an attack.
                      </p>
                    );
                  })()}
                </div>

                <div className="feature-grid">

                  {(anomaly.shap_explanation.feature_contributions || [])
                    .slice(0, 5)
                    .map((item) => (

                      <div
                        className="feature-item"
                        key={item.feature}
                      >

                        <span>
                          {item.feature.replaceAll("_", " ")}
                        </span>

                        <strong>
                          {item.value}
                        </strong>

                        <small>
                          SHAP: {item.shap_value > 0 ? "+" : ""}
                          {item.shap_value}
                          {" · "}
                          {item.direction === "lowers_score"
                            ? "Lowers model score"
                            : item.direction === "raises_score"
                            ? "Raises model score"
                            : "Neutral"}
                        </small>

                      </div>

                    ))}

                </div>

                <small>
                  Baseline model score:{" "}
                  {Number(anomaly.shap_explanation.base_value).toFixed(4)}
                </small>
              </>

            ) : (

              <p>
                SHAP explanation is unavailable for this window.
              </p>

            )}

          </details>

        </div>

      ))}

    </div>

  )}

</section>

        {/* INCIDENT MANAGEMENT */}

        <section
          className="panel incidents-panel"
          id="incidents"
        >

          <div className="section-heading">

            <div>
              <div className="eyebrow">
                INCIDENT MANAGEMENT
              </div>

              <h2>Active Incidents</h2>
            </div>

            <div className="incident-controls">

              <div className="search-box">
                <FaSearch />

                <input
                  placeholder="Search incidents..."
                  value={search}
                  onChange={(e) =>
                    setSearch(e.target.value)
                  }
                />
              </div>

              <select
                value={filter}
                onChange={(e) =>
                  setFilter(e.target.value)
                }
              >
                <option value="all">All</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>

            </div>

          </div>

          <div className="incident-table">

            <div className="incident-header">
              <span>Incident</span>
              <span>Agent</span>
              <span>Events</span>
              <span>Risk</span>
              <span>MITRE</span>
              <span />
            </div>

            {loading ? (
              <Empty text="Loading incidents..." />
            ) : filteredIncidents.length === 0 ? (
              <Empty text="No incidents match the current filter." />
            ) : (
              filteredIncidents.map((incident) => {

                const risk = getRisk(incident);
                const priority = getPriority(incident);

                return (
                  <button
                    className="incident-row"
                    key={incident.incident_id}
                    onClick={() =>
                      openIncident(incident)
                    }
                  >

                    
<div className="incident-identity">
  <strong>
    {incident.incident_id}
  </strong>

  <small>
    {incident.category || "security"}
  </small>

  <small className="incident-received-time">
    Received:{" "}
    {formatDate(
      incident.first_seen ||
      incident.last_seen ||
      incident.timestamp
    )}
  </small>
</div>
x

                    <div>
                      {incident.agent_name || "—"}
                    </div>

                    <div className="event-number">
                      {incident.event_count || 0}
                    </div>

                    <div>
                      <RiskBadge
                        risk={risk}
                        priority={priority}
                      />
                    </div>

                    <div className="mitre-tags">
                      {(incident.mitre_techniques || [])
                        .slice(0, 3)
                        .map((technique) => (
                          <span key={technique}>
                            {technique}
                          </span>
                        ))}

                      {(incident.mitre_techniques || []).length > 3 && (
                        <span>
                          +{incident.mitre_techniques.length - 3}
                        </span>
                      )}
                    </div>

                    <FaChevronRight className="row-arrow" />

                  </button>
                );
              })
            )}

          </div>

        </section>

        {/* LOWER INTELLIGENCE */}

        <section className="bottom-grid">

          <div
            className="panel"
            id="mitre"
          >

            <PanelHeader
              eyebrow="THREAT INTELLIGENCE"
              title="MITRE ATT&CK"
              count="Top techniques"
            />

            {mitreCounts.length === 0 ? (
              <Empty text="No MITRE techniques detected." />
            ) : (
              <div className="mitre-list">

                {mitreCounts.map(
                  ([technique, count]) => (
                    <div
                      className="mitre-row"
                      key={technique}
                    >

                      <div className="mitre-id">
                        <FaBug />
                        <strong>{technique}</strong>
                      </div>

                      <div className="mitre-track">
                        <span
                          style={{
                            width: `${Math.min(
                              100,
                              (count /
                                mitreCounts[0][1]) *
                                100
                            )}%`,
                          }}
                        />
                      </div>

                      <strong>{count}</strong>

                    </div>
                  )
                )}

              </div>
            )}

          </div>

          <div
            className="panel"
            id="investigation"
          >

            <PanelHeader
              eyebrow="AI INVESTIGATION"
              title="Investigation Intelligence"
              count={<FaBrain />}
            />

            <div className="investigation-content">

              <div className="investigation-icon">
                <FaBrain />
              </div>

              <h3>
                Automated incident reasoning
              </h3>

              <p>
                Select an incident above to inspect its
                correlated events, MITRE mappings, timeline
                and explainable risk factors.
              </p>

              <div className="engine-tags">
                <span>Correlation</span>
                <span>Risk Intelligence</span>
                <span>MITRE Mapping</span>
                <span>Explainability</span>
              </div>

            </div>

          </div>

        </section>

      </main>

      {/* INVESTIGATION DRAWER */}

      {selectedIncident && (
        <div
          className="drawer-backdrop"
          onClick={() => setSelectedIncident(null)}
        >

          <aside
            className="investigation-drawer"
            onClick={(e) =>
              e.stopPropagation()
            }
          >

            <div className="drawer-header">

              <div>
                <div className="eyebrow">
                  INCIDENT INVESTIGATION
                </div>

                <h2>
                  {selectedIncident.incident_id}
                </h2>
              </div>

              <button
                onClick={() =>
                  setSelectedIncident(null)
                }
              >
                ×
              </button>

            </div>

            <div className="drawer-risk">

              <div>
                <span>Risk score</span>
                <strong>
                  {getRisk(selectedIncident)}
                </strong>
              </div>

              <RiskBadge
                risk={getRisk(selectedIncident)}
                priority={getPriority(selectedIncident)}
              />

            </div>

            <div className="drawer-section">

              <h3>Incident Overview</h3>

              <div className="detail-grid">

                <Detail
                  label="Events"
                  value={
                    selectedIncident.event_count || 0
                  }
                />

                <Detail
                  label="Agent"
                  value={
                    (selectedIncident.agents || []).join(", ") || "—"
                  }
                />

                <Detail
                  label="First Seen"
                  value={
                    formatDate(
                      selectedIncident.first_seen
                    )
                  }
                />

                <Detail
                  label="Last Seen"
                  value={
                    formatDate(
                      selectedIncident.last_seen
                    )
                  }
                />

              </div>

            </div>

            <div className="drawer-section">

              <h3>
                MITRE ATT&CK
              </h3>

              <div className="drawer-tags">

                {(selectedIncident.mitre_techniques || [])
                  .map((technique) => (
                    <span key={technique}>
                      {technique}
                    </span>
                  ))}

                {(selectedIncident.mitre_techniques || [])
                  .length === 0 && (
                    <small>
                      No mapped techniques.
                    </small>
                  )}

              </div>

            </div>

            <div className="drawer-section">

              <h3>
                Risk Explanation
              </h3>
<p className="risk-summary">
  {selectedIncident.risk?.explanation?.summary ||
   selectedIncident.explainability?.assessment ||
   selectedIncident.risk_explanation?.summary ||
   selectedIncident.risk_explanation ||
   selectedIncident.summary ||
   "Risk explanation is not available for this incident."}
</p>

              <div className="factor-list">

                {(
                  selectedIncident.risk?.explanation?.factors ||
                  selectedIncident.explainability?.contributing_factors ||[]
                ).map((factor, index) => (
                  <div
                    className="factor"
                    key={index}
                  >
                    <div>
                      <strong>
                        {factor.factor}
                      </strong>

                      <small>
                        {factor.reason}
                      </small>
                    </div>

                    <b>
                      +{factor.contribution}
                    </b>
                  </div>
                ))}

              </div>

            </div>

            <div className="drawer-section">

              <h3>
                <FaNetworkWired />
                Event Timeline
              </h3>

              <div className="timeline">

                {(selectedIncident.timeline || selectedIncident.events || []).map(
                  (event, index) => (
                    <div
                      className="timeline-item"
                      key={index}
                    >

                      <span className="timeline-dot" />

                      <div>
                        <strong>
                          {event.description || event.event_type || "Security event"}
                        </strong>

                        <small>
                          {formatDate(
                            event.timestamp
                          )}
                        </small>

                        <p>
                          Risk {event.risk_score ?? 0}
                          {" · "}
                          {event.event_type || "security"}
                          {" · "}
                          {event.user || "unknown user"}
                        </p>
                      </div>

                    </div>
                  )
                )}

              </div>

            </div>
            <div className="drawer-section">
              <h3>Investigation Memory</h3>
              {(selectedIncident.investigation_memory?.similar_incidents || []).length > 0 ? (
                <div className="factor-list">
                  {selectedIncident.investigation_memory.similar_incidents.map((match, index) => (
                    <div className="factor" key={`${match.incident_id}-${index}`}>
                      <div>
                        <strong>{match.incident_id}</strong>
                        <small>
                          Similarity: {((match.similarity_score || 0) * 100).toFixed(1)}%
                          {" · "}Priority: {match.priority || "unknown"}
                        </small>
                        <small>{match.summary || "Historical incident match"}</small>
                      </div>
                      <b>{match.risk_score ?? 0}</b>
                    </div>
                  ))}
               </div>
             ) : (
               <p>No similar historical incidents found.</p>
            )}
          </div>

          <div className="drawer-section">
            <h3>Decision Intelligence</h3>
            
            <p className="risk-summary">
              {selectedIncident.explainability?.assessment ||
              "Review the incident evidence and risk indicators."}
            </p>
            <h4>Investigation Focus</h4>
            <ul>
              {(selectedIncident.decision_intelligence?.investigation_focus || []).map(
                (item, index) => <li key={index}>{item}</li>
                )}
            </ul>
            <h4>Decision Rationale</h4>
            <ul>
    {(selectedIncident.decision_intelligence?.rationale || []).map(
      (item, index) => <li key={index}>{item}</li>
    )}
  </ul>
</div>

<div className="drawer-section">
  <h3>Recommended Actions</h3>

  {(selectedIncident.recommendations?.recommendations || []).length > 0 ? (
    <div className="factor-list">
      {selectedIncident.recommendations.recommendations.map((item, index) => (
        <div className="factor" key={index}>
          <div>
            <strong>{item.action || "Investigate incident"}</strong>
            <small>{item.reason || "Review the associated evidence."}</small>
          </div>
        </div>
      ))}
    </div>
  ) : (
    <p>No recommendations available.</p>
  )}

  <small>
    Automated response:{" "}
    {selectedIncident.recommendations?.automated_response ? "Enabled" : "Not enabled"}
  </small>
</div>

          </aside>

        </div>
      )}

    </div>
  );
}


/* ------------------------------------------------ */
/* SMALL COMPONENTS */
/* ------------------------------------------------ */

function StatCard({
  label,
  value,
  description,
  icon,
  type,
}) {
  return (
    <div className={`stat-card stat-${type}`}>

      <div className="stat-top">
        <span>{label}</span>
        <div>{icon}</div>
      </div>

      <strong>{value}</strong>

      <small>{description}</small>

    </div>
  );
}


function PanelHeader({
  eyebrow,
  title,
  count,
}) {
  return (
    <div className="panel-header">

      <div>
        <div className="eyebrow">
          {eyebrow}
        </div>

        <h2>{title}</h2>
      </div>

      {count && (
        <span className="panel-count">
          {count}
        </span>
      )}

    </div>
  );
}


function RiskBar({
  label,
  count,
  total,
  type,
}) {
  const width =
    total > 0
      ? `${Math.max(2, (count / total) * 100)}%`
      : "0%";

  return (
    <div className="risk-row">

      <span>{label}</span>

      <strong>{count}</strong>

      <div className="risk-track">
        <span
          className={`risk-fill ${type}`}
          style={{ width }}
        />
      </div>

    </div>
  );
}


function RiskBadge({
  risk,
  priority,
}) {
  return (
    <span className={`risk-badge ${priority}`}>
      {priority}
      <b>{risk}</b>
    </span>
  );
}


function Detail({
  label,
  value,
}) {
  return (
    <div className="detail">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}


function Empty({ text }) {
  return (
    <div className="empty">
      <FaClock />
      <span>{text}</span>
    </div>
  );
}


function formatDate(value) {
  if (!value) return "—";

  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}
