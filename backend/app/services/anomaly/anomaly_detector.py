from datetime import datetime
from collections import defaultdict


# ============================================================
# BEHAVIORAL ANOMALY DETECTION
# ============================================================
#
# This module looks for suspicious PATTERNS across a batch of
# security events, rather than judging a single event on its
# own (that is what event_classifier.py already does).
#
# It detects:
#
#   1. Brute-force style authentication activity
#   2. A single user authenticating from too many source IPs
#   3. Off-hours activity for sensitive event categories
#   4. Sudden spikes of events from a single agent
#   5. Login -> privilege escalation patterns
#
# Every anomaly is returned as an explainable dictionary,
# following the same "factors + reason" style used by
# event_classifier.py and risk_engine.py, so the frontend can
# display *why* something was flagged.
# ============================================================


# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

# Brute-force detection
FAILED_LOGIN_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 300  # 5 minutes

# Multiple source IPs for one account
DISTINCT_IP_THRESHOLD = 3
ACCOUNT_WINDOW_SECONDS = 600  # 10 minutes

# Off-hours activity (24h clock, server/local time)
OFF_HOURS_START_HOUR = 0
OFF_HOURS_END_HOUR = 5
OFF_HOURS_CATEGORIES = {
    "authentication",
    "privilege",
    "malware",
    "file_integrity",
}

# Event spikes from a single agent
EVENT_SPIKE_THRESHOLD = 10
EVENT_SPIKE_WINDOW_SECONDS = 120  # 2 minutes

# Login -> privilege escalation pattern
ESCALATION_WINDOW_SECONDS = 300  # 5 minutes

MAX_ANOMALY_SCORE = 100


# ============================================================
# HELPERS
# ============================================================

def parse_timestamp(timestamp):
    """
    Convert an ISO timestamp string into a datetime object.
    Returns None if the timestamp is missing or invalid.
    """

    if not timestamp:
        return None

    try:
        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

    except (ValueError, TypeError):
        return None


def get_event_user(event):
    """
    Return the most relevant user associated with an event.
    """

    return (
        event.get("source_user")
        or event.get("destination_user")
    )


def is_failed_login(event):
    """
    Decide whether an event represents a failed authentication
    attempt.

    Works whether or not event_classifier.py has already run:
    prefers the "category" field when present, and falls back
    to keyword matching on the rule description otherwise.
    """

    rule = (event.get("rule_description") or "").lower()

    keywords = [
        "failed login",
        "authentication failure",
        "authentication failed",
        "invalid user",
        "brute force",
    ]

    if any(keyword in rule for keyword in keywords):
        return True

    if event.get("category") == "authentication" and "fail" in rule:
        return True

    return False


def is_privilege_event(event):
    """
    Decide whether an event represents privilege / root activity.
    """

    if event.get("category") == "privilege":
        return True

    rule = (event.get("rule_description") or "").lower()

    keywords = ["sudo", "privilege", "root", "escalation"]

    return any(keyword in rule for keyword in keywords)


def sorted_by_time(events):
    """
    Return events sorted by timestamp, dropping events with no
    parseable timestamp (they cannot take part in time-based
    pattern detection).
    """

    timed_events = []

    for event in events:

        timestamp = parse_timestamp(event.get("timestamp"))

        if timestamp:
            timed_events.append((timestamp, event))

    timed_events.sort(key=lambda pair: pair[0])

    return timed_events


def build_anomaly(
    anomaly_type,
    entity,
    score,
    summary,
    factors,
    evidence_events,
):
    """
    Build a single explainable anomaly object, in the same
    "summary + factors" shape used elsewhere in the project.
    """

    score = max(0, min(score, MAX_ANOMALY_SCORE))

    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"

    return {
        "anomaly_type": anomaly_type,
        "entity": entity,
        "score": score,
        "severity": severity,
        "event_count": len(evidence_events),
        "first_seen": evidence_events[0].get("timestamp")
            if evidence_events else None,
        "last_seen": evidence_events[-1].get("timestamp")
            if evidence_events else None,
        "explanation": {
            "summary": summary,
            "factors": factors,
        },
        "events": evidence_events,
    }


# ============================================================
# 1. BRUTE-FORCE AUTHENTICATION DETECTION
# ============================================================

def detect_brute_force(events):
    """
    Flag accounts / source IPs with repeated failed logins
    inside a short sliding time window.
    """

    anomalies = []

    failed_logins = [
        event for event in events if is_failed_login(event)
    ]

    # Group failed logins by the most relevant identity: the
    # account being targeted, falling back to the source IP
    # when no account name is present.

    grouped = defaultdict(list)

    for event in failed_logins:

        identity = (
            get_event_user(event)
            or event.get("source_ip")
            or "unknown"
        )

        grouped[identity].append(event)

    for identity, identity_events in grouped.items():

        timed_events = sorted_by_time(identity_events)

        # Sliding window over the sorted timestamps looking for
        # FAILED_LOGIN_THRESHOLD attempts inside the window.

        window_start = 0

        for window_end in range(len(timed_events)):

            end_time = timed_events[window_end][0]

            while (
                end_time - timed_events[window_start][0]
            ).total_seconds() > BRUTE_FORCE_WINDOW_SECONDS:
                window_start += 1

            attempts_in_window = window_end - window_start + 1

            if attempts_in_window >= FAILED_LOGIN_THRESHOLD:

                evidence = [
                    event
                    for _, event in
                    timed_events[window_start:window_end + 1]
                ]

                factors = [
                    {
                        "factor": "Failed login count",
                        "value": attempts_in_window,
                        "reason": (
                            f"{attempts_in_window} failed login "
                            f"attempts for '{identity}' occurred "
                            f"within {BRUTE_FORCE_WINDOW_SECONDS} "
                            "seconds."
                        ),
                    }
                ]

                score = min(
                    50 + (attempts_in_window - FAILED_LOGIN_THRESHOLD) * 5,
                    MAX_ANOMALY_SCORE,
                )

                anomalies.append(
                    build_anomaly(
                        anomaly_type="brute_force",
                        entity=identity,
                        score=score,
                        summary=(
                            f"Possible brute-force activity against "
                            f"'{identity}'."
                        ),
                        factors=factors,
                        evidence_events=evidence,
                    )
                )

                # Move past this window so the same burst isn't
                # reported once per event inside it.
                window_start = window_end + 1

    return anomalies


# ============================================================
# 2. MULTIPLE SOURCE IPS FOR ONE ACCOUNT
# ============================================================

def detect_multiple_source_ips(events):
    """
    Flag an account that is seen authenticating from too many
    distinct source IPs within a short window (credential
    sharing, credential stuffing, or a compromised account).
    """

    anomalies = []

    login_events = [
        event
        for event in events
        if get_event_user(event) and event.get("source_ip")
    ]

    grouped = defaultdict(list)

    for event in login_events:
        grouped[get_event_user(event)].append(event)

    for user, user_events in grouped.items():

        timed_events = sorted_by_time(user_events)

        window_start = 0

        for window_end in range(len(timed_events)):

            end_time = timed_events[window_end][0]

            while (
                end_time - timed_events[window_start][0]
            ).total_seconds() > ACCOUNT_WINDOW_SECONDS:
                window_start += 1

            window_events = [
                event
                for _, event in
                timed_events[window_start:window_end + 1]
            ]

            distinct_ips = {
                event.get("source_ip") for event in window_events
            }

            if len(distinct_ips) >= DISTINCT_IP_THRESHOLD:

                factors = [
                    {
                        "factor": "Distinct source IPs",
                        "value": sorted(distinct_ips),
                        "reason": (
                            f"User '{user}' was seen from "
                            f"{len(distinct_ips)} different source "
                            f"IPs within {ACCOUNT_WINDOW_SECONDS} "
                            "seconds."
                        ),
                    }
                ]

                score = min(
                    40 + (len(distinct_ips) - DISTINCT_IP_THRESHOLD) * 10,
                    MAX_ANOMALY_SCORE,
                )

                anomalies.append(
                    build_anomaly(
                        anomaly_type="multiple_source_ips",
                        entity=user,
                        score=score,
                        summary=(
                            f"User '{user}' authenticated from an "
                            "unusually high number of source IPs."
                        ),
                        factors=factors,
                        evidence_events=window_events,
                    )
                )

                window_start = window_end + 1

    return anomalies


# ============================================================
# 3. OFF-HOURS ACTIVITY
# ============================================================

def is_off_hours(timestamp):
    """
    Decide whether a timestamp falls inside the configured
    off-hours window.
    """

    hour = timestamp.hour

    if OFF_HOURS_START_HOUR <= OFF_HOURS_END_HOUR:
        return OFF_HOURS_START_HOUR <= hour < OFF_HOURS_END_HOUR

    # Handles a window that wraps past midnight, e.g. 22 -> 5
    return hour >= OFF_HOURS_START_HOUR or hour < OFF_HOURS_END_HOUR


def detect_off_hours_activity(events):
    """
    Flag sensitive-category events that happen outside normal
    working hours, grouped per agent so a single quiet night
    doesn't generate one anomaly per event.
    """

    anomalies = []

    grouped = defaultdict(list)

    for event in events:

        timestamp = parse_timestamp(event.get("timestamp"))

        if not timestamp:
            continue

        category = event.get("category")

        if category not in OFF_HOURS_CATEGORIES:
            continue

        if not is_off_hours(timestamp):
            continue

        agent = event.get("agent_name") or event.get("agent_id") or "unknown"

        grouped[agent].append(event)

    for agent, agent_events in grouped.items():

        categories_seen = sorted({
            event.get("category") for event in agent_events
        })

        factors = [
            {
                "factor": "Off-hours event count",
                "value": len(agent_events),
                "reason": (
                    f"{len(agent_events)} security-relevant events "
                    f"on '{agent}' occurred between "
                    f"{OFF_HOURS_START_HOUR:02d}:00 and "
                    f"{OFF_HOURS_END_HOUR:02d}:00, outside normal "
                    "business hours."
                ),
            },
            {
                "factor": "Categories involved",
                "value": categories_seen,
                "reason": (
                    "The off-hours activity includes categories "
                    "that are normally treated as sensitive: "
                    + ", ".join(categories_seen) + "."
                ),
            },
        ]

        score = min(30 + len(agent_events) * 5, MAX_ANOMALY_SCORE)

        anomalies.append(
            build_anomaly(
                anomaly_type="off_hours_activity",
                entity=agent,
                score=score,
                summary=(
                    f"Sensitive activity on '{agent}' during "
                    "off-hours."
                ),
                factors=factors,
                evidence_events=sorted(
                    agent_events,
                    key=lambda event: event.get("timestamp") or "",
                ),
            )
        )

    return anomalies


# ============================================================
# 4. EVENT SPIKES PER AGENT
# ============================================================

def detect_event_spikes(events):
    """
    Flag an agent producing an unusually large burst of events
    in a short window, which can indicate a scripted attack,
    a misbehaving service, or log flooding.
    """

    anomalies = []

    grouped = defaultdict(list)

    for event in events:

        agent = event.get("agent_name") or event.get("agent_id")

        if not agent:
            continue

        grouped[agent].append(event)

    for agent, agent_events in grouped.items():

        timed_events = sorted_by_time(agent_events)

        window_start = 0

        for window_end in range(len(timed_events)):

            end_time = timed_events[window_end][0]

            while (
                end_time - timed_events[window_start][0]
            ).total_seconds() > EVENT_SPIKE_WINDOW_SECONDS:
                window_start += 1

            events_in_window = window_end - window_start + 1

            if events_in_window >= EVENT_SPIKE_THRESHOLD:

                evidence = [
                    event
                    for _, event in
                    timed_events[window_start:window_end + 1]
                ]

                factors = [
                    {
                        "factor": "Event volume",
                        "value": events_in_window,
                        "reason": (
                            f"'{agent}' generated {events_in_window} "
                            f"events within "
                            f"{EVENT_SPIKE_WINDOW_SECONDS} seconds, "
                            "well above normal volume."
                        ),
                    }
                ]

                score = min(
                    40 + (events_in_window - EVENT_SPIKE_THRESHOLD) * 3,
                    MAX_ANOMALY_SCORE,
                )

                anomalies.append(
                    build_anomaly(
                        anomaly_type="event_spike",
                        entity=agent,
                        score=score,
                        summary=(
                            f"Unusual spike of events from '{agent}'."
                        ),
                        factors=factors,
                        evidence_events=evidence,
                    )
                )

                window_start = window_end + 1

    return anomalies


# ============================================================
# 5. LOGIN -> PRIVILEGE ESCALATION PATTERN
# ============================================================

def detect_login_then_privilege_escalation(events):
    """
    Flag a user who authenticates and then performs privileged
    or root-level activity shortly afterward. On its own this
    can be normal admin behavior, so it is scored lower than
    brute force or spikes, but it is still useful context for
    an investigation timeline.
    """

    anomalies = []

    grouped = defaultdict(list)

    for event in events:

        user = get_event_user(event)

        if user:
            grouped[user].append(event)

    for user, user_events in grouped.items():

        timed_events = sorted_by_time(user_events)

        for i, (login_time, login_event) in enumerate(timed_events):

            # We only care about SUCCESSFUL authentication here.
            successful_login = (
                login_event.get("category") == "authentication"
                and not is_failed_login(login_event)
            )

            if not successful_login:
                continue

            for privilege_time, privilege_event in timed_events[i + 1:]:

                seconds_after = (
                    privilege_time - login_time
                ).total_seconds()

                if seconds_after > ESCALATION_WINDOW_SECONDS:
                    break

                if is_privilege_event(privilege_event):

                    factors = [
                        {
                            "factor": "Login-to-privilege gap",
                            "value": seconds_after,
                            "reason": (
                                f"User '{user}' authenticated and "
                                "performed privileged activity "
                                f"{int(seconds_after)} seconds later."
                            ),
                        }
                    ]

                    anomalies.append(
                        build_anomaly(
                            anomaly_type="login_then_privilege_escalation",
                            entity=user,
                            score=45,
                            summary=(
                                f"'{user}' escalated to privileged "
                                "activity shortly after logging in."
                            ),
                            factors=factors,
                            evidence_events=[
                                login_event,
                                privilege_event,
                            ],
                        )
                    )

                    break

    return anomalies


# ============================================================
# MAIN ENTRY POINT
# ============================================================

def detect_behavioral_anomalies(events):
    """
    Run every behavioral anomaly check against a batch of
    (ideally already-classified) security events and return a
    combined, score-sorted list of anomalies.
    """

    if not events:
        return []

    anomalies = []

    anomalies.extend(detect_brute_force(events))
    anomalies.extend(detect_multiple_source_ips(events))
    anomalies.extend(detect_off_hours_activity(events))
    anomalies.extend(detect_event_spikes(events))
    anomalies.extend(detect_login_then_privilege_escalation(events))

    anomalies.sort(key=lambda anomaly: anomaly["score"], reverse=True)

    return anomalies


def annotate_events_with_anomalies(events):
    """
    Attach a "behavioral_anomalies" list to every event that
    was used as evidence for at least one anomaly, so the
    dashboard can highlight flagged events inline without a
    second lookup.

    Returns the same events list, mutated in place, along with
    the full anomaly list.
    """

    anomalies = detect_behavioral_anomalies(events)

    for event in events:
        event.setdefault("behavioral_anomalies", [])

    for anomaly in anomalies:

        for evidence_event in anomaly["events"]:

            evidence_event.setdefault(
                "behavioral_anomalies", []
            ).append(
                {
                    "anomaly_type": anomaly["anomaly_type"],
                    "severity": anomaly["severity"],
                }
            )

    return events, anomalies


# ============================================================
# QUICK MANUAL TEST
# ============================================================
#
# Run directly with:
#   python -m app.services.anomaly.anomaly_detector
#
# This is not a replacement for real unit tests (that's Riya's
# module), just a fast sanity check while developing.

if __name__ == "__main__":

    sample_events = [
        {
            "timestamp": "2026-01-05T02:00:00Z",
            "agent_id": "001",
            "agent_name": "web-01",
            "rule_description": "Failed login attempt",
            "category": "authentication",
            "source_ip": "10.0.0.5",
            "destination_user": "admin",
        },
        {
            "timestamp": "2026-01-05T02:00:30Z",
            "agent_id": "001",
            "agent_name": "web-01",
            "rule_description": "Failed login attempt",
            "category": "authentication",
            "source_ip": "10.0.0.5",
            "destination_user": "admin",
        },
        {
            "timestamp": "2026-01-05T02:01:00Z",
            "agent_id": "001",
            "agent_name": "web-01",
            "rule_description": "Failed login attempt",
            "category": "authentication",
            "source_ip": "10.0.0.9",
            "destination_user": "admin",
        },
        {
            "timestamp": "2026-01-05T02:01:30Z",
            "agent_id": "001",
            "agent_name": "web-01",
            "rule_description": "Failed login attempt",
            "category": "authentication",
            "source_ip": "10.0.0.9",
            "destination_user": "admin",
        },
        {
            "timestamp": "2026-01-05T02:02:00Z",
            "agent_id": "001",
            "agent_name": "web-01",
            "rule_description": "Failed login attempt",
            "category": "authentication",
            "source_ip": "10.0.0.20",
            "destination_user": "admin",
        },
    ]

    results = detect_behavioral_anomalies(sample_events)

    for result in results:
        print(result["anomaly_type"], "-", result["explanation"]["summary"])
