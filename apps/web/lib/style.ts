export function bandClass(band?: string | null) {
  switch (band) {
    case "CRITICAL":
    case "HIGH":
      return "bg-carmine/10 text-carmine border-carmine/30";
    case "MEDIUM":
      return "bg-brass/10 text-brass border-brass/40";
    case "LOW":
      return "bg-forest/10 text-forest border-forest/30";
    case "PASS":
    case "GRANTED":
    case "ON_TRACK":
      return "bg-forest/10 text-forest border-forest/30";
    case "UNKNOWN":
    case "STALE":
    case "REQUESTED":
    case "DUE_SOON":
      return "bg-brass/10 text-brass border-brass/40";
    case "FAIL":
    case "OVERDUE":
    case "REVOKED":
    case "DENIED":
    case "EXPIRED":
      return "bg-carmine/10 text-carmine border-carmine/30";
    case "OPEN":
      return "bg-brass/10 text-brass border-brass/40";
    case "CLOSED":
      return "bg-forest/10 text-forest border-forest/30";
    default:
      return "bg-navy/5 text-navy border-rule";
  }
}

export function outcomeClass(outcome?: string | null) {
  switch (outcome) {
    case "ALLOW":
      return "border-forest bg-forest text-white";
    case "REVIEW":
      return "border-brass bg-brass text-white";
    case "BLOCK":
    case "DENY":
      return "border-carmine bg-carmine text-white";
    default:
      return "border-rule bg-panel text-ink";
  }
}
