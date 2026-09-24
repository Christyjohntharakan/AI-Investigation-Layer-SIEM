from app.services.explainability.shap_explainer import (
    explain_event_features
)

from app.services.explainability.llm_explainer import (
    generate_explanation
)


def explain_event(event):
    """
    Generate an explanation for a security event.

    Steps:
    1. Identify important features.
    2. Generate a human-readable explanation.
    """

    feature_contributions = explain_event_features(
        event
    )

    explanation = generate_explanation(
        event,
        feature_contributions
    )

    return {
        "event_type":
            event.get("event_type"),

        "risk_score":
            event.get("risk_score", 0),

        "priority":
            event.get("priority"),

        "feature_contributions":
            feature_contributions,

        "explanation":
            explanation["explanation"],

        "explanation_model":
            explanation["model"]
    }


def explain_events(events):
    """
    Generate explanations for multiple events.
    """

    results = []

    for event in events:

        results.append(
            explain_event(event)
        )

    return results