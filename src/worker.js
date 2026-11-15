const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/health") return json({ ok: true, service: "Spore Microfinance API", databaseConfigured: Boolean(env.DB) });
    if (url.pathname === "/api/enquiries" && request.method === "POST") {
      if (!env.DB) return json({ error: "Enquiry service is not configured yet." }, 503);
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
      const name = String(body.name || "").trim(), phone = String(body.phone || "").trim(), email = String(body.email || "").trim();
      const type = body.type === "loan" ? "loan" : "account";
      if (name.length < 2 || name.length > 120 || phone.length < 7 || phone.length > 24) return json({ error: "Enter a valid name and phone number." }, 422);
      if (email.length > 254 || (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return json({ error: "Enter a valid email address." }, 422);
      let details = {};
      if (type === "loan") {
        const amount = Number(body.amount);
        if (!Number.isSafeInteger(amount) || amount < 100000 || amount > 100000000) return json({ error: "Amount must be between UGX 100,000 and UGX 100,000,000." }, 422);
        details = { amount, purpose: String(body.purpose || "").slice(0, 80), term: String(body.term || "").slice(0, 30), notes: String(body.notes || "").slice(0, 1000) };
      }
      try {
        await env.DB.prepare("INSERT INTO enquiries (type, full_name, phone, email, details_json, status, created_at) VALUES (?, ?, ?, ?, ?, 'new', datetime('now'))").bind(type, name, phone, email || null, JSON.stringify(details)).run();
        return json({ ok: true, message: "Enquiry received. Our team can contact you after review." }, 201);
      } catch { return json({ error: "Unable to save enquiry. Please try again later." }, 500); }
    }
    if (url.pathname.startsWith("/api/")) return json({ error: "API route not found." }, 404);
    return env.ASSETS.fetch(request);
  }
};