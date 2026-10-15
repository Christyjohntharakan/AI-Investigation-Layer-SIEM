import { useState } from "react";
export default function InvestigationPanel({
    incidents = []
}) {
    const [timelineFilter, setTimelineFilter] = useState("all");
    const [expandedEvent, setExpandedEvent] = useState(null);
    const latestIncident =
        incidents.length > 0 ? incidents[0] : null;

    if (!latestIncident) {
        return (
            <div className="panel">
                <span className="section-label">
                    AI INVESTIGATION
                </span>

                <h2>
                    Investigation Intelligence
                </h2>

                <div className="empty-small">
                    Waiting for correlated security activity.
                </div>
            </div>
        );
    }

    const risk = latestIncident.risk || {};
    const explainability =
        latestIncident.explainability || {};

    const decision =
        latestIncident.decision_intelligence || {};

    const recommendations =
        latestIncident.recommendations || {};

    const memory =
        latestIncident.investigation_memory || {};

    const timeline =
        latestIncident.timeline || [];

    const mitreTechniques =
        latestIncident.mitre_techniques || [];

    const agents =
        latestIncident.agents || [];

    const users =
        latestIncident.users || [];

    const priority =
        risk.priority ||
        latestIncident.priority ||
        "low";

    const riskScore =
        risk.score ??
        latestIncident.max_risk_score ??
        0;

    const factors =
        explainability.contributing_factors || [];

    const similarIncidents =
        memory.similar_incidents || [];

    const focus =
        decision.investigation_focus || [];

    const recommendationList =
        recommendations.recommendations || [];

    return (
        <div className="panel investigation-panel">

            {/* HEADER */}

            <div className="panel-heading">
                <div>
                    <span className="section-label">
                        AI INVESTIGATION
                    </span>

                    <h2>
                        Investigation Intelligence
                    </h2>
                </div>

                <span
                    className={`priority priority-${priority}`}
                >
                    {priority}
                </span>
            </div>

            {/* INCIDENT ID */}

            <div className="investigation-id">
                {latestIncident.incident_id}
            </div>

            <p className="investigation-summary">
                {latestIncident.summary ||
                    explainability.assessment ||
                    "Security incident detected."}
            </p>

            {/* CORE METRICS */}

            <div className="investigation-metrics">

                <div>
                    <span>Risk</span>
                    <strong>{riskScore}</strong>
                </div>

                <div>
                    <span>Events</span>
                    <strong>
                        {latestIncident.event_count || 0}
                    </strong>
                </div>

                <div>
                    <span>MITRE</span>
                    <strong>
                        {mitreTechniques.length}
                    </strong>
                </div>

                <div>
                    <span>Historical</span>
                    <strong>
                        {similarIncidents.length}
                    </strong>
                </div>

            </div>

            {/* RISK EXPLANATION */}

            <div className="risk-explanation">

                <span>
                    WHY THIS RISK?
                </span>

                {factors.length === 0 ? (
                    <div className="empty-small">
                        No contributing risk factors available.
                    </div>
                ) : (
                    factors.slice(0, 4).map(
                        (factor, index) => (
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
                        )
                    )
                )}

            </div>

            {/* DECISION INTELLIGENCE */}

            <div className="investigation-section">

                <span className="section-label">
                    DECISION INTELLIGENCE
                </span>

                {focus.length === 0 ? (
                    <div className="empty-small">
                        No investigation focus generated.
                    </div>
                ) : (
                    <ul className="investigation-list">
                        {focus.slice(0, 4).map(
                            (item, index) => (
                                <li key={index}>
                                    {item}
                                </li>
                            )
                        )}
                    </ul>
                )}

            </div>

            {/* INVESTIGATION MEMORY */}

            <div className="investigation-section">

                <span className="section-label">
                    INVESTIGATION MEMORY
                </span>

                <div className="memory-summary">
                    <strong>
                        {similarIncidents.length}
                    </strong>

                    <span>
                        similar historical incident
                        {similarIncidents.length === 1
                            ? ""
                            : "s"} found
                    </span>
                </div>

                {similarIncidents.length > 0 && (
                    <div className="memory-list">
                        {similarIncidents
                            .slice(0, 3)
                            .map((match, index) => (
                                <div
                                    className="memory-item"
                                    key={index}
                                >
                                    <strong>
                                        {match.incident_id ||
                                            `Historical Match ${index + 1}`}
                                    </strong>

                                    {match.score !== undefined && (
                                        <small>
                                            Similarity:{" "}
                                            {Number(match.score).toFixed(3)}
                                        </small>
                                    )}
                                </div>
                            ))}
                    </div>
                )}

            </div>

            {/* RECOMMENDATIONS */}

            <div className="investigation-section">

                <span className="section-label">
                    ANALYST RECOMMENDATIONS
                </span>

                {recommendationList.length === 0 ? (
                    <div className="empty-small">
                        No recommendations generated.
                    </div>
                ) : (
                    <div className="recommendation-list">

                        {recommendationList
                            .slice(0, 4)
                            .map((recommendation, index) => (
                                <div
                                    className="recommendation-item"
                                    key={index}
                                >
                                    <strong>
                                        {recommendation.action}
                                    </strong>

                                    <small>
                                        {recommendation.reason}
                                    </small>
                                </div>
                            ))}

                    </div>
                )}

                <div className="recommendation-note">
                    Advisory only — no automated response action
                    is executed.
                </div>

            </div>

            {/* INTERACTIVE INCIDENT TIMELINE */}
            <div className="investigation-timeline-section">
                <div className="timeline-heading-row">
        <div>
            <span className="section-label">
                INCIDENT TIMELINE
            </span>
            <p className="timeline-subtitle">
                Explore the sequence of security events
            </p>
        </div>

        <span className="timeline-count">
            {timeline.length} events
        </span>
        </div>

    <div className="timeline-filter-row">
        {[
            { label: "All events", value: "all" },
            { label: "High risk", value: "high" },
            { label: "Critical", value: "critical" },
        ].map((filter) => (
            <button
                key={filter.value}
                type="button"
                className={`timeline-filter ${
                    timelineFilter === filter.value ? "active" : ""
                }`}
                onClick={() => setTimelineFilter(filter.value)}
            >
                {filter.label}
            </button>
        ))}
    </div>

    {timeline.length === 0 ? (
        <div className="empty-small">
            No timeline events available.
        </div>
    ) : (
        <div className="timeline-list">
            {timeline
                .filter((event) => {
                    const priority = String(
                        event.priority || "low"
                    ).toLowerCase();

                    if (timelineFilter === "high") {
                        return priority === "high";
                    }

                    if (timelineFilter === "critical") {
                        return priority === "critical";
                    }

                    return true;
                })
                .map((event, index) => {
                    const eventKey =
                        `${event.sequence ?? index}-${event.timestamp ?? ""}-${index}`;

                    const isExpanded = expandedEvent === eventKey;
                    const priority = String(
                        event.priority || "low"
                    ).toLowerCase();

                    return (
                        <div
                            className={`timeline-item ${
                                isExpanded ? "expanded" : ""
                            }`}
                            key={eventKey}
                        >
                            <div className="timeline-marker" />

                            <div className="timeline-event-card">
                                <button
                                    type="button"
                                    className="timeline-event-toggle"
                                    onClick={() =>
                                        setExpandedEvent(
                                            isExpanded ? null : eventKey
                                        )
                                    }
                                    aria-expanded={isExpanded}
                                >
                                    <div className="timeline-event-main">
                                        <div className="timeline-event-top">
                                            <span className="timeline-sequence">
                                                EVENT {event.sequence ?? index + 1}
                                            </span>

                                            <span
                                                className={`timeline-priority priority-${priority}`}
                                            >
                                                {priority.toUpperCase()}
                                            </span>
                                        </div>

                                        <strong>
                                            {event.event_type ||
                                                event.category ||
                                                "Security event"}
                                        </strong>

                                        <small className="timeline-timestamp">
                                            {event.timestamp || "Unknown time"}
                                        </small>

                                        <p>
                                            {event.description ||
                                                "Event activity recorded."}
                                        </p>
                                    </div>

                                    <div className="timeline-event-side">
                                        <span className="timeline-risk">
                                            {event.risk_score ?? 0}
                                            <small>RISK</small>
                                        </span>

                                        <span className="timeline-chevron">
                                            {isExpanded ? "−" : "+"}
                                        </span>
                                    </div>
                                </button>

                                {isExpanded && (
                                    <div className="timeline-event-details">
                                        <div className="timeline-detail-grid">
                                            <div>
                                                <small>USER</small>
                                                <strong>{event.user || "Unknown"}</strong>
                                            </div>

                                            <div>
                                                <small>AGENT</small>
                                                <strong>{event.agent || "Unknown"}</strong>
                                            </div>

                                            <div>
                                                <small>SOURCE IP</small>
                                                <strong>{event.source_ip || "Not available"}</strong>
                                            </div>

                                            <div>
                                                <small>DESTINATION IP</small>
                                                <strong>{event.destination_ip || "Not available"}</strong>
                                            </div>
                                        </div>

                                        <div className="timeline-mitre-details">
                                            <small>MITRE ATT&CK TECHNIQUES</small>
                                            <div className="timeline-tags">
                                                {(event.mitre_techniques || []).length > 0
                                                    ? event.mitre_techniques.map((technique, i) => (
                                                        <span key={i}>
                                                            {typeof technique === "string"
                                                                ? technique
                                                                : technique.name || technique.id || JSON.stringify(technique)}
                                                        </span>
                                                    ))
                                                    : <span>None recorded</span>}
                                            </div>

                                            <small>MITRE TACTICS</small>
                                            <div className="timeline-tags">
                                                {(event.mitre_tactics || []).length > 0
                                                    ? event.mitre_tactics.map((tactic, i) => (
                                                        <span key={i}>
                                                            {typeof tactic === "string"
                                                                ? tactic
                                                                : tactic.name || tactic.id || JSON.stringify(tactic)}
                                                        </span>
                                                    ))
                                                    : <span>None recorded</span>}
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    );
                })}
        </div>
    )}

    {timeline.filter((event) => {
        const priority = String(event.priority || "low").toLowerCase();

        if (timelineFilter === "high") return priority === "high";
        if (timelineFilter === "critical") return priority === "critical";
        return true;
    }).length === 0 && timeline.length > 0 && (
        <div className="empty-small">
            No events match this priority filter.
        </div>
    )}
</div>


            {/* CONTEXT */}

            <div className="investigation-context">

                <div>
                    <span>Agents</span>
                    <strong>
                        {agents.length || "—"}
                    </strong>
                </div>

                <div>
                    <span>Users</span>
                    <strong>
                        {users.length || "—"}
                    </strong>
                </div>

                <div>
                    <span>First Seen</span>
                    <strong>
                        {latestIncident.first_seen || "—"}
                    </strong>
                </div>

                <div>
                    <span>Last Seen</span>
                    <strong>
                        {latestIncident.last_seen || "—"}
                    </strong>
                </div>

            </div>

        </div>
    );
}