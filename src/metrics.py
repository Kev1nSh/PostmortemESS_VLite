from prometheus_client import Counter, Histogram

ANALYSIS_REQUESTS = Counter(
    "postmortemess_analysis_requests_total",
    "Total number of analysis requests"
)

ANALYSIS_TOTAL = Counter(
    "postmortemess_analysis_total",
    "Total number of analyses"
)

ANALYSIS_ERRORS_TOTAL = Counter(
    "postmortemess_analysis_errors_total",
    "Total number of analysis errors"
)

ANALYSIS_DURATION_SECONDS = Histogram(
    "postmortemess_analysis_duration_seconds",
    "Duration of analysis in seconds"
)