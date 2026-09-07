export default function StatCard({
    title,
    value,
    subtitle,
    color
}) {

    return (

        <div className="stat-card">

            <div className="stat-top">

                <span className="stat-title">
                    {title}
                </span>

                <span
                    className="stat-indicator"
                    style={{
                        backgroundColor: color
                    }}
                />

            </div>

            <div
                className="stat-value"
                style={{
                    color: color
                }}
            >
                {value}
            </div>

            <div className="stat-subtitle">
                {subtitle}
            </div>

        </div>

    );

}