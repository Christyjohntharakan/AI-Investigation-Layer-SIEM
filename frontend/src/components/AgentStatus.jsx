export default function AgentStatus({
    logs = [],
    agents = 0
}) {

    const agentMap = {};

    logs.forEach(event => {

        const id =
            event.agent_id ||
            event.agent_name ||
            "unknown";

        agentMap[id] = {

            name:
                event.agent_name ||
                id,

            ip:
                event.agent_ip ||
                "—",

            lastSeen:
                event.timestamp ||
                null,

            events:
                (agentMap[id]?.events || 0) + 1

        };

    });

    const agentList =
        Object.values(agentMap);

    return (

        <div className="panel agent-panel">

            <div className="panel-heading">

                <div>

                    <span className="section-label">
                        ENDPOINTS
                    </span>

                    <h2>
                        Agent Status
                    </h2>

                </div>

                <span className="online-count">
                    {agents} detected
                </span>

            </div>

            <div className="agent-list">

                {agentList.length === 0 ? (

                    <div className="empty-small">
                        No agents detected
                    </div>

                ) : (

                    agentList.map(
                        agent => (

                            <div
                                className="agent-row"
                                key={agent.name}
                            >

                                <div className="agent-info">

                                    <span className="agent-dot"></span>

                                    <div>

                                        <strong>
                                            {agent.name}
                                        </strong>

                                        <small>
                                            {agent.ip}
                                        </small>

                                    </div>

                                </div>

                                <div className="agent-metrics">

                                    <strong>
                                        {agent.events}
                                    </strong>

                                    <small>
                                        events
                                    </small>

                                </div>

                            </div>

                        )
                    )

                )}

            </div>

        </div>

    );

}