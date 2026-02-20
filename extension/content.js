// ===== ENTROPY CALCULATOR =====
function calculateEntropy(str) {
  const map = {};
  for (let char of str) {
    map[char] = (map[char] || 0) + 1;
  }

  let entropy = 0;
  for (let char in map) {
    const p = map[char] / str.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

// ===== MAIN ANALYZER FUNCTION =====
export function analyzeURL(url) {
  let riskScore = 0;
  let reasons = [];

  // Basic validation
  try {
    new URL(url);
  } catch {
    return {
      riskScore: 100,
      riskLevel: "High Risk",
      reasons: ["Invalid URL format"]
    };
  }

  const parsedURL = new URL(url);
  const domain = parsedURL.hostname.toLowerCase();

  // 1️⃣ URL Length Check
  if (url.length > 75) {
    riskScore += 15;
    reasons.push("Unusually long URL detected");
  }

  // 2️⃣ Suspicious Keywords
  const suspiciousKeywords = [
    "login", "verify", "update", "secure",
    "account", "bank", "password", "signin"
  ];

  suspiciousKeywords.forEach(keyword => {
    if (url.includes(keyword)) {
      riskScore += 10;
      reasons.push(`Suspicious keyword detected: ${keyword}`);
    }
  });

  // 3️⃣ Digit Ratio Check
  const digitCount = (url.match(/\d/g) || []).length;
  const digitRatio = digitCount / url.length;

  if (digitRatio > 0.2) {
    riskScore += 10;
    reasons.push("High digit ratio detected");
  }

  // 4️⃣ Excess Subdomains
  const subdomainCount = domain.split(".").length - 2;

  if (subdomainCount > 2) {
    riskScore += 10;
    reasons.push("Too many subdomains detected");
  }

  // 5️⃣ IP Address Instead of Domain
  const ipRegex = /^\d{1,3}(\.\d{1,3}){3}$/;

  if (ipRegex.test(domain)) {
    riskScore += 20;
    reasons.push("IP address used instead of domain");
  }

  // 6️⃣ HTTPS Check
  if (parsedURL.protocol !== "https:") {
    riskScore += 10;
    reasons.push("Non-HTTPS connection");
  }

  // 7️⃣ Entropy Check
  const entropy = calculateEntropy(domain);

  if (entropy > 4) {
    riskScore += 15;
    reasons.push("High entropy domain (random-looking)");
  }

  // Cap score
  riskScore = Math.min(riskScore, 100);

  // Risk classification
  let riskLevel = "Safe";
  if (riskScore >= 70) riskLevel = "High Risk";
  else if (riskScore >= 40) riskLevel = "Suspicious";

  return {
    riskScore,
    riskLevel,
    reasons
  };
}