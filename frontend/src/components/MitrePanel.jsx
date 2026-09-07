export default function MitrePanel({
    incidents = []
}) {

    const techniques = {};

    incidents.forEach(
        incident => {

            (
                incident.mitre_techniques ||
                []
            ).forEach(
                technique => {

                    techniques[technique] =
                        (
                            techniques[technique] ||
                            0
                        ) + 1;

                }
            );

        }
    );

    const sortedTechniques =
        Object.entries(techniques)
            .sort(
                (a, b) => b[1] - a[1]
            )
            .slice(0, 6);

    return (

        <div className="panel mitre-panel">

            <div className="panel-heading">

                <div>

                    <span className="section-label">
                        THREAT FRAMEWORK
                    </span>

                    <h2>
                        MITRE ATT&CK
                    </h2>

                </div>

                <span className="mitre-count">
                    {Object.keys(techniques).length}
                </span>

            </div>

            {sortedTechniques.length === 0 ? (

                <div className="empty-small">

                    No MITRE techniques detected
                    in current incidents.

                </div>

            ) : (

                <div className="technique-list">

                    {sortedTechniques.map(
                        ([technique, count]) => (

                            <div
                                className="technique-row"
                                key={technique}
                            >

                                <span className="technique-id">
                                    {technique}
                                </span>

                                <div className="technique-bar">

                                    <span
                                        style={{
                                            width:
                                                `${Math.min(
                                                    count * 25,
                                                    100
                                                )}%`
                                        }}
                                    />

                                </div>

                                <span className="technique-count">
                                    {count}
                                </span>

                            </div>

                        )
                    )}

                </div>

            )}

        </div>

    );

}