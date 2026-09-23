from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List

from sklearn.ensemble import IsolationForest


WINDOW_MINUTES = 5


class IsolationForestDetector:
    """
    ML-based behavioral anomaly detector for Wazuh events.

    Events are grouped into time windows and converted into
    behavioral features before Isolation Forest analysis.
    """

    FEATURE_NAMES = [
        "total_events",
        "auth_failures",
        "auth_successes",
        "sudo_events",
        "file_changes",
        "security_events",
        "unique_users",
        "avg_severity",
        "max_severity",
        "rule_group_diversity",
        "package_config_events",
    ]

    def __init__(
        self,
        contamination: float = 0.10,
        random_state: int = 42,
    ):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
        )
        self.is_fitted = False

    def _parse_time(self, event: Dict[str, Any]) -> datetime:
        timestamp = event.get("timestamp")

        if not timestamp:
            return datetime.min

        try:
            return datetime.fromisoformat(
                str(timestamp).replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            return datetime.min

    def _build_windows(
        self,
        events: List[Dict[str, Any]],
    ) -> List[List[Dict[str, Any]]]:

        valid_events = [
            event for event in events
            if self._parse_time(event) != datetime.min
        ]

        valid_events.sort(key=self._parse_time)

        if not valid_events:
            return []

        windows = []
        current_window = []
        window_start = self._parse_time(valid_events[0])
        window_end = window_start + timedelta(minutes=WINDOW_MINUTES)

        for event in valid_events:
            event_time = self._parse_time(event)

            if event_time < window_end:
                current_window.append(event)
            else:
                if current_window:
                    windows.append(current_window)

                current_window = [event]
                window_start = event_time
                window_end = window_start + timedelta(
                    minutes=WINDOW_MINUTES
                )

        if current_window:
            windows.append(current_window)

        return windows

    def _extract_features(
        self,
        window: List[Dict[str, Any]],
    ) -> List[float]:

        if not window:
            return [0.0] * len(self.FEATURE_NAMES)

        auth_failures = 0
        auth_successes = 0
        sudo_events = 0
        file_changes = 0
        security_events = 0
        package_config_events = 0

        users = set()
        severities = []
        rule_groups = set()

        for event in window:
            groups = set(event.get("rule_groups") or [])
            rule_groups.update(groups)

            severity = event.get("severity")
            if severity is not None:
                try:
                    severities.append(float(severity))
                except (ValueError, TypeError):
                    pass

            for user_field in (
                "source_user",
                "destination_user",
            ):
                user = event.get(user_field)
                if user:
                    users.add(str(user))

            if "authentication_failed" in groups:
                auth_failures += 1

            if "authentication_success" in groups:
                auth_successes += 1

            if "sudo" in groups:
                sudo_events += 1

            if any(
                group.startswith("syscheck")
                for group in groups
            ):
                file_changes += 1

            if "apparmor" in groups or "sca" in groups:
                security_events += 1

            if (
                "dpkg" in groups
                or "config_changed" in groups
            ):
                package_config_events += 1

        avg_severity = (
            sum(severities) / len(severities)
            if severities
            else 0.0
        )

        max_severity = max(severities) if severities else 0.0

        return [
            float(len(window)),
            float(auth_failures),
            float(auth_successes),
            float(sudo_events),
            float(file_changes),
            float(security_events),
            float(len(users)),
            round(avg_severity, 3),
            max_severity,
            float(len(rule_groups)),
            float(package_config_events),
        ]

    def build_features(
        self,
        events: List[Dict[str, Any]],
    ) -> List[List[float]]:

        windows = self._build_windows(events)

        return [
            self._extract_features(window)
            for window in windows
        ]

    def fit(self, events: List[Dict[str, Any]]) -> None:

        features = self.build_features(events)

        if not features:
            raise ValueError(
                "No valid behavioral windows available for training."
            )

        self.model.fit(features)
        self.is_fitted = True

    def detect(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        if not self.is_fitted:
            raise RuntimeError(
                "Isolation Forest model must be fitted before detection."
            )

        windows = self._build_windows(events)

        if not windows:
            return []

        features = [
            self._extract_features(window)
            for window in windows
        ]

        predictions = self.model.predict(features)
        scores = self.model.decision_function(features)

        results = []

        for window, prediction, score, feature_values in zip(
            windows,
            predictions,
            scores,
            features,
        ):
            results.append(
                {
                    "is_anomaly": bool(prediction == -1),
                    "model": "Isolation Forest",
                    "decision_score": round(float(score), 4),
                    "event_count": len(window),
                    "first_seen": window[0].get("timestamp"),
                    "last_seen": window[-1].get("timestamp"),
                    "features": dict(
                        zip(
                            self.FEATURE_NAMES,
                            feature_values,
                        )
                    ),
                    "events": window,
                }
            )

        return results


def detect_isolation_forest_anomalies(
    training_events: List[Dict[str, Any]],
    events_to_check: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    detector = IsolationForestDetector()

    detector.fit(training_events)

    return detector.detect(events_to_check)