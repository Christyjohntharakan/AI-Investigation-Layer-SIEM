export default function InvestigationPanel({
    incidents = []
}) {

    const latestIncident =
        incidents.length > 0
            ? incidents[0]
            : null;

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
                    Waiting for correlated security
                    activity.
                </div>

            </div>

        );

    }

    return (

        <div className="panel investigation-panel">

            <div className="panel-heading">

                <div>

                    <span className="section-label">
                        AI INVESTIGATION
                    </span>

                    <h2>
                        Latest Investigation
                    </h2>

                </div>

                <span
                    className={
                        `priority priority-${latestIncident.priority}`
                    }
                >
                    {latestIncident.priority}
                </span>

            </div>

            <div className="investigation-id">

                {latestIncident.incident_id}

            </div>

            <p className="investigation-summary">

                {
                    latestIncident
                        .risk_explanation
                        ?.summary ||
                    "Security incident detected."
                }

            </p>

            <div className="investigation-metrics">

                <div>

                    <span>
                        Risk
                    </span>

                    <strong>
                        {
                            latestIncident
                                .max_risk_score
                        }
                    </strong>

                </div>

                <div>

                    <span>
                        Events
                    </span>

                    <strong>
                        {
                            latestIncident
                                .event_count
                        }
                    </strong>

                </div>

                <div>

                    <span>
                        MITRE
                    </span>

                    <strong>
                        {
                            (
                                latestIncident
                                    .mitre_techniques ||
                                []
                            ).length
                        }
                    </strong>

                </div>

            </div>

            <div className="risk-explanation">

                <span>
                    RISK EXPLANATION
                </span>

                {(
                    latestIncident
                        .risk_explanation
                        ?.factors ||
                    []
                ).slice(0, 3).map(
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
                )}

            </div>

        </div>

    );

}