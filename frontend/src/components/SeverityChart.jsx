export default function SeverityChart({
    incidents = []
}) {

    const high =
        incidents.filter(
            i =>
                i.priority === "high" ||
                i.priority === "critical"
        ).length;

    const medium =
        incidents.filter(
            i =>
                i.priority === "medium"
        ).length;

    const low =
        incidents.filter(
            i =>
                i.priority === "low"
        ).length;

    const total =
        incidents.length || 1;

    const data = [

        {
            label: "High",
            value: high,
            className: "bar-high"
        },

        {
            label: "Medium",
            value: medium,
            className: "bar-medium"
        },

        {
            label: "Low",
            value: low,
            className: "bar-low"
        }

    ];

    return (

        <div className="panel risk-panel">

            <div className="panel-heading">

                <div>

                    <span className="section-label">
                        RISK ANALYTICS
                    </span>

                    <h2>
                        Incident Risk
                    </h2>

                </div>

                <span className="section-count">
                    {incidents.length}
                </span>

            </div>

            <div className="risk-chart">

                {data.map(item => {

                    const percentage =
                        (item.value / total) * 100;

                    return (

                        <div
                            className="risk-row"
                            key={item.label}
                        >

                            <div className="risk-label">

                                <span>
                                    {item.label}
                                </span>

                                <strong>
                                    {item.value}
                                </strong>

                            </div>

                            <div className="risk-track">

                                <div
                                    className={
                                        `risk-bar ${item.className}`
                                    }
                                    style={{
                                        width:
                                            `${Math.max(
                                                percentage,
                                                item.value
                                                    ? 4
                                                    : 0
                                            )}%`
                                    }}
                                />

                            </div>

                        </div>

                    );

                })}

            </div>

            <div className="risk-footer">

                <span>
                    Average incident risk
                </span>

                <strong>

                    {incidents.length
                        ? Math.round(
                            incidents.reduce(
                                (sum, incident) =>
                                    sum +
                                    Number(
                                        incident.max_risk_score ||
                                        0
                                    ),
                                0
                            ) /
                            incidents.length
                        )
                        : 0
                    }

                    /100

                </strong>

            </div>

        </div>

    );

}