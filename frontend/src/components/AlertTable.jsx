export default function AlertTable({
    incidents = []
}) {

    if (!incidents.length) {

        return (

            <div className="table-card empty-state">

                <div className="empty-icon">
                    ✓
                </div>

                <h3>
                    No correlated incidents
                </h3>

                <p>
                    The investigation engine has not
                    produced any incidents yet.
                </p>

            </div>

        );

    }

    return (

        <div className="table-card">

            <div className="table-wrapper">

                <table>

                    <thead>

                        <tr>

                            <th>Incident</th>
                            <th>Agent</th>
                            <th>Events</th>
                            <th>Risk</th>
                            <th>Priority</th>
                            <th>MITRE ATT&CK</th>

                        </tr>

                    </thead>

                    <tbody>

                        {incidents.map(
                            incident => (

                                <tr
                                    key={
                                        incident.incident_id
                                    }
                                >

                                    <td>

                                        <span className="incident-id">
                                            {
                                                incident.incident_id
                                            }
                                        </span>

                                    </td>

                                    <td>
                                        {
                                            incident.agent_name ||
                                            incident.agent_id ||
                                            "Unknown"
                                        }
                                    </td>

                                    <td>

                                        <span className="event-count">
                                            {
                                                incident.event_count
                                            }
                                        </span>

                                    </td>

                                    <td>

                                        <span
                                            className={
                                                `risk-score risk-${incident.priority}`
                                            }
                                        >
                                            {
                                                incident.max_risk_score
                                            }
                                        </span>

                                    </td>

                                    <td>

                                        <span
                                            className={
                                                `priority priority-${incident.priority}`
                                            }
                                        >
                                            {
                                                incident.priority
                                            }
                                        </span>

                                    </td>

                                    <td>

                                        <div className="mitre-tags">

                                            {(
                                                incident.mitre_techniques ||
                                                []
                                            ).length > 0

                                                ? incident.mitre_techniques.map(
                                                    technique => (

                                                        <span
                                                            key={
                                                                technique
                                                            }
                                                            className="mitre-tag"
                                                        >
                                                            {technique}
                                                        </span>

                                                    )
                                                )

                                                : (
                                                    <span className="muted">
                                                        None
                                                    </span>
                                                )
                                            }

                                        </div>

                                    </td>

                                </tr>

                            )
                        )}

                    </tbody>

                </table>

            </div>

        </div>

    );

}