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

import API from "../services/api";
import "../styles/dashboard.css";

export default function Dashboard() {
  const [logs, setLogs] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);

  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [lastUpdated, setLastUpdated] = useState(null);

  async function loadDashboard() {
    try {
      const [logsResponse, incidentsResponse] = await Promise.all([
        API.get("/logs"),
        API.get("/incidents"),
      ]);

      const logData = Array.isArray(logsResponse.data)
        ? logsResponse.data
        : [];

      const incidentData = Array.isArray(incidentsResponse.data)
        ? incidentsResponse.data
        : [];

      setLogs(logData);
      setIncidents(incidentData);
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
    loadDashboard();

    const interval = setInterval(loadDashboard, 5000);

    return () => clearInterval(interval);
  }, []);

  const getRisk = (incident) =>
    incident?.max_risk_score ??
    incident?.risk_score ??
    incident?.risk?.maximum ??
    0;

  const getPriority = (incident) =>
    (
      incident?.priority ??
      incident?.risk?.priority ??
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

        </section>

        {/* ANALYTICS */}

        <section className="analytics-grid">

          <div className="panel risk-panel">

            <PanelHeader
              eyebrow="RISK ANALYTICS"
              title="Incident Risk"
              count={incidents.length}
            />

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

                    <div>
                      <strong>
                        {incident.incident_id}
                      </strong>

                      <small>
                        {incident.category || "security"}
                      </small>
                    </div>

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
                    selectedIncident.agent_name || "—"
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
                {
                  selectedIncident
                    .risk_explanation
                    ?.summary ||
                  selectedIncident.summary ||
                  "No explanation available."
                }
              </p>

              <div className="factor-list">

                {(
                  selectedIncident
                    .risk_explanation
                    ?.factors || []
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

                {(selectedIncident.events || []).map(
                  (event, index) => (
                    <div
                      className="timeline-item"
                      key={index}
                    >

                      <span className="timeline-dot" />

                      <div>
                        <strong>
                          {event.rule_description ||
                            event.rule_id ||
                            "Security event"}
                        </strong>

                        <small>
                          {formatDate(
                            event.timestamp
                          )}
                        </small>

                        <p>
                          Risk {event.risk_score ?? 0}
                          {" · "}
                          {event.category || "security"}
                        </p>
                      </div>

                    </div>
                  )
                )}

              </div>

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