from datetime import datetime


# Convert timestamp into datetime
def parse_timestamp(timestamp):
    if not timestamp:
        return None

    if isinstance(timestamp, datetime):
        return timestamp

    try:
        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except (ValueError, TypeError):
        return None


# Get a useful description for the event
def get_event_description(event):
    return (
        event.get("rule_description")
        or event.get("message")
        or event.get("event_type")
        or "Security event"
    )


# Reconstruct the investigation timeline
def reconstruct_timeline(events):

    if not events:
        return {
            "event_count": 0,
            "first_seen": None,
            "last_seen": None,
            "duration_seconds": 0,
            "timeline": []
        }

    valid_events = []

    # Keep events that have valid timestamps
    for event in events:

        timestamp = parse_timestamp(
            event.get("timestamp")
        )

        if timestamp:
            valid_events.append(
                (timestamp, event)
            )

    # Sort events from oldest to newest
    valid_events.sort(
        key=lambda item: item[0]
    )

    if not valid_events:
        return {
            "event_count": len(events),
            "first_seen": None,
            "last_seen": None,
            "duration_seconds": 0,
            "timeline": []
        }

    first_timestamp = valid_events[0][0]
    last_timestamp = valid_events[-1][0]

    duration_seconds = (
        last_timestamp - first_timestamp
    ).total_seconds()

    timeline = []

    previous_timestamp = None

    # Build each timeline event
    for index, (timestamp, event) in enumerate(
        valid_events,
        start=1
    ):

        if previous_timestamp is None:
            time_since_previous = 0
        else:
            time_since_previous = (
                timestamp - previous_timestamp
            ).total_seconds()

        timeline_event = {

            "sequence": index,

            "timestamp":
                timestamp.isoformat(),

            "time_since_previous_seconds":
                time_since_previous,

            "event_type":
                event.get("event_type"),

            "category":
                event.get("category"),

            "description":
                get_event_description(event),

            "agent_name":
                event.get("agent_name"),

            "agent_id":
                event.get("agent_id"),

            "source_ip":
                event.get("source_ip"),

            "destination_ip":
                event.get("destination_ip"),

            "source_user":
                event.get("source_user"),

            "destination_user":
                event.get("destination_user"),

            "severity":
                event.get("severity"),

            "risk_score":
                event.get("risk_score", 0),

            "priority":
                event.get("priority"),

            "mitre_techniques":
                event.get(
                    "mitre_techniques",
                    []
                ),

            "mitre_tactics":
                event.get(
                    "mitre_tactics",
                    []
                )
        }

        timeline.append(
            timeline_event
        )

        previous_timestamp = timestamp

    return {

        "event_count":
            len(timeline),

        "first_seen":
            first_timestamp.isoformat(),

        "last_seen":
            last_timestamp.isoformat(),

        "duration_seconds":
            duration_seconds,

        "timeline":
            timeline
    }