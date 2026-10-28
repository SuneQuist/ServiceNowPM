
export function assessRisk(incident) {
    const impact = Number(incident.impact);
    const urgency = Number(incident.urgency);
    const priority = Number(incident.priority);

    // ServiceNow Incident scores: 1 is highest.
    const valid =
        [1, 2, 3].includes(impact) &&
        [1, 2, 3].includes(urgency) &&
        Number.isInteger(priority) &&
        priority >= 1 &&
        priority <= 5;

    if (!valid) {
        return {
            level: 'Unknown',
            recommendation: 'Verify the Incident scores.'
        };
    }

    let level;
    let recommendation;

    if (priority <= 2) {
        level = 'High operational priority';
        recommendation =
            'Promptly assess security exposure and coordinate remediation.';
    } else if (priority === 3) {
        level = 'Medium operational priority';
        recommendation =
            'Review vulnerability applicability and plan mitigation.';
    } else {
        level = 'Low operational priority';
        recommendation =
            'Verify exposure before scheduling routine remediation.';
    }

    return { level, recommendation };
}
