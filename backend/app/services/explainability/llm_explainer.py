def generate_explanation(event, feature_contributions):
    """
    Generate a human-readable explanation
    from the important security features.

    This is the explanation layer. It can later
    be connected to Llama 3.1 through an API.
    """

    event_type = event.get(
        "event_type",
        "security event"
    )

    category = event.get(
        "category",
        "unknown"
    )

    risk_score = event.get(
        "risk_score",
        0
    )

    priority = event.get(
        "priority",
        "unknown"
    )

    explanations = []

    for feature in feature_contributions:

        name = feature.get("feature")
        value = feature.get("value")

        explanations.append(
            f"{name}: {value}"
        )

    feature_text = ", ".join(
        explanations
    )

    explanation = (
        f"The event was classified as "
        f"{event_type} in the {category} category. "
        f"It has a risk score of {risk_score} "
        f"and a priority of {priority}. "
        f"The main factors considered were: "
        f"{feature_text}."
    )

    return {
        "explanation": explanation,
        "model": "Llama 3.1 compatible explanation layer"
    }