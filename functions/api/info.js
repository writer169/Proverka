export async function onRequest(context) {
  const { request, env } = context;

  // Key protection
  const url = new URL(request.url);
  const key = url.searchParams.get("key");
  const SECRET = env.ACCESS_KEY || "changeme";

  if (key !== SECRET) {
    return new Response(JSON.stringify({ error: "Forbidden" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }

  const headers = {};
  for (const [name, value] of request.headers.entries()) {
    headers[name.toLowerCase()] = value;
  }

  // Cloudflare-specific data
  const cf = request.cf || {};

  // Parse user agent
  const ua = headers["user-agent"] || "";

  // Determine device type from CF or UA
  let deviceType = "desktop";
  if (cf.deviceType) {
    deviceType = cf.deviceType; // mobile, tablet, desktop
  } else {
    const uaLower = ua.toLowerCase();
    if (/tablet|ipad/.test(uaLower)) deviceType = "tablet";
    else if (/mobile|android|iphone/.test(uaLower)) deviceType = "mobile";
  }

  // Select important headers to expose
  const importantHeaders = [
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "referer",
    "dnt",
    "sec-gpc",
    "upgrade-insecure-requests",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-user",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-model",
    "cache-control",
    "pragma",
    "connection",
    "x-forwarded-for",
    "via",
    "te",
    "priority",
  ];

  const filteredHeaders = {};
  for (const h of importantHeaders) {
    if (headers[h] !== undefined) {
      filteredHeaders[h] = headers[h];
    }
  }

  const result = {
    // Basic request info
    ip: headers["cf-connecting-ip"] || headers["x-forwarded-for"] || "unknown",
    ipv6: headers["cf-connecting-ipv6"] || null,
    country: cf.country || headers["cf-ipcountry"] || null,
    city: cf.city || null,
    region: cf.region || null,
    regionCode: cf.regionCode || null,
    timezone: cf.timezone || null,
    asn: cf.asn ? `AS${cf.asn}` : null,
    asOrganization: cf.asOrganization || null,
    postalCode: cf.postalCode || null,
    latitude: cf.latitude || null,
    longitude: cf.longitude || null,
    // Request metadata
    serverTime: new Date().toISOString(),
    rayId: headers["cf-ray"] || null,
    protocol: cf.httpProtocol || url.protocol.replace(":", ""),
    tlsVersion: cf.tlsVersion || null,
    tlsCipher: cf.tlsCipher || null,
    deviceType: deviceType,
    // Visitor type from cf-visitor header
    cfVisitor: headers["cf-visitor"] ? JSON.parse(headers["cf-visitor"]) : null,
    // All important headers
    headers: filteredHeaders,
  };

  return new Response(JSON.stringify(result), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}