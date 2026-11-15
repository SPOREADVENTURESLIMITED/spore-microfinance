const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
});
const hex = (bytes) => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, "0")).join("");
const randomHex = (size = 32) => {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return hex(bytes);
};
const digest = async (value) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: 100000 }, key, 256);
  return hex(bits);
}
const cookieToken = (request) => {
  const raw = request.headers.get("cookie") || "";
  const match = raw.match(/(?:^|;\\s*)spore_session=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
};
async function currentUser(request, env) {
  const token = cookieToken(request);
  if (!token || !env.DB) return null;
  const row = await env.DB.prepare("SELECT c.id,c.full_name,c.phone,c.email,c.role FROM sessions s JOIN customers c ON c.id=s.customer_id WHERE s.token_hash=? AND s.expires_at > datetime('now')").bind(await digest(token)).first();
  return row || null;
}
const sessionCookie = (token, maxAge = 604800) => `spore_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const validPhone = (v) => /^\\+?[0-9 ()-]{7,24}$/.test(v);
const safeUser = (u) => ({ id: u.id, fullName: u.full_name, phone: u.phone, email: u.email, role: u.role });
async function audit(env, actor, action, entityType, entityId, details = {}) {
  await env.DB.prepare("INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?)")
    .bind(actor?.id || null, action, entityType, entityId || null, JSON.stringify(details)).run();
}
async function handleApi(request, env) {
  const url = new URL(request.url), path = url.pathname, method = request.method;
  if (!env.DB) return json({ error: "Database is not configured." }, 503);
  if (path === "/api/health" && method === "GET") return json({ ok: true, service: "Spore Microfinance API", databaseConfigured: true });
  if (path === "/api/auth/register" && method === "POST") {
    let b; try { b = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
    const name = String(b.fullName || "").trim(), phone = String(b.phone || "").trim(), email = String(b.email || "").trim().toLowerCase(), password = String(b.password || "");
    if (name.length < 2 || name.length > 120 || !validPhone(phone)) return json({ error: "Enter a valid full name and phone number." }, 422);
    if (email.length > 254 || (email && !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email))) return json({ error: "Enter a valid email address." }, 422);
    if (password.length < 10 || password.length > 128) return json({ error: "Password must be 10–128 characters." }, 422);
    const salt = randomHex(16), hash = await passwordHash(password, salt);
    try {
      const result = await env.DB.prepare("INSERT INTO customers(full_name,phone,email,password_hash,password_salt) VALUES(?,?,?,?,?)").bind(name, phone, email || null, hash, salt).run();
      const user = { id: result.meta.last_row_id, full_name: name, phone, email, role: "customer" };
      const token = randomHex(32), tokenHash = await digest(token);
      await env.DB.prepare("INSERT INTO sessions(customer_id,token_hash,expires_at) VALUES(?,?,datetime('now','+7 days'))").bind(user.id, tokenHash).run();
      await audit(env, user, "customer.registered", "customer", user.id);
      return json({ ok: true, user: safeUser(user) }, 201, { "set-cookie": sessionCookie(token) });
    } catch { return json({ error: "This phone number may already be registered." }, 409); }
  }
  if (path === "/api/auth/login" && method === "POST") {
    let b; try { b = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
    const phone = String(b.phone || "").trim(), password = String(b.password || "");
    const user = await env.DB.prepare("SELECT * FROM customers WHERE phone=?").bind(phone).first();
    if (!user || (await passwordHash(password, user.password_salt)) !== user.password_hash) return json({ error: "Phone number or password is incorrect." }, 401);
    const token = randomHex(32);
    await env.DB.prepare("INSERT INTO sessions(customer_id,token_hash,expires_at) VALUES(?,?,datetime('now','+7 days'))").bind(user.id, await digest(token)).run();
    return json({ ok: true, user: safeUser(user) }, 200, { "set-cookie": sessionCookie(token) });
  }
  if (path === "/api/auth/logout" && method === "POST") {
    const token = cookieToken(request);
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }
  if (path === "/api/admin/bootstrap" && method === "POST") {
    if (!env.ADMIN_BOOTSTRAP_TOKEN) return json({ error: "Admin bootstrap is not configured. Add ADMIN_BOOTSTRAP_TOKEN as a Worker secret." }, 503);
    let b; try { b = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
    if (!b.token || b.token !== env.ADMIN_BOOTSTRAP_TOKEN) return json({ error: "Invalid bootstrap token." }, 403);
    const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM customers WHERE role='admin'").first();
    if (count.total > 0) return json({ error: "An administrator is already configured. Ask the existing administrator for access." }, 409);
    const phone = String(b.phone || "").trim();
    const user = await env.DB.prepare("SELECT id,full_name,phone,email,role FROM customers WHERE phone=?").bind(phone).first();
    if (!user) return json({ error: "Register a customer account with this phone number first, then bootstrap it." }, 404);
    await env.DB.prepare("UPDATE customers SET role='admin',updated_at=datetime('now') WHERE id=?").bind(user.id).run();
    await audit(env, { id: user.id }, "admin.bootstrapped", "customer", user.id);
    return json({ ok: true, message: "Administrator access enabled. Sign in again to refresh your session." });
  }
  const user = await currentUser(request, env);
  if (path === "/api/me" && method === "GET") return user ? json({ user: safeUser(user) }) : json({ error: "Please sign in." }, 401);
  if (path === "/api/loans" && method === "POST") {
    if (!user) return json({ error: "Please sign in to apply." }, 401);
    let b; try { b = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
    const amount = Number(b.amount), term = Number(b.termMonths), purpose = String(b.purpose || "").trim(), notes = String(b.notes || "").trim();
    if (!Number.isSafeInteger(amount) || amount < 100000 || amount > 100000000) return json({ error: "Amount must be between UGX 100,000 and UGX 100,000,000." }, 422);
    if (![3,6,9,12,18,24].includes(term) || purpose.length < 2 || purpose.length > 100 || notes.length > 1000) return json({ error: "Check the loan purpose, term and notes." }, 422);
    const result = await env.DB.prepare("INSERT INTO loan_applications(customer_id,amount_ugx,purpose,term_months,notes) VALUES(?,?,?,?,?)").bind(user.id, amount, purpose, term, notes).run();
    await audit(env, user, "loan.submitted", "loan_application", result.meta.last_row_id, { amount, termMonths: term });
    return json({ ok: true, applicationId: result.meta.last_row_id, message: "Your application has been submitted for review." }, 201);
  }
  if (path === "/api/loans" && method === "GET") {
    if (!user) return json({ error: "Please sign in." }, 401);
    const { results } = await env.DB.prepare("SELECT id,amount_ugx,purpose,term_months,status,admin_note,created_at,updated_at FROM loan_applications WHERE customer_id=? ORDER BY created_at DESC").bind(user.id).all();
    return json({ applications: results || [] });
  }
  if (path.startsWith("/api/admin/")) {
    if (!user) return json({ error: "Please sign in." }, 401);
    if (user.role !== "admin") return json({ error: "Administrator access required." }, 403);
    if (path === "/api/admin/summary" && method === "GET") {
      const [customers, applications, pending, approved] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS total FROM customers WHERE role='customer'").first(),
        env.DB.prepare("SELECT COUNT(*) AS total FROM loan_applications").first(),
        env.DB.prepare("SELECT COUNT(*) AS total FROM loan_applications WHERE status IN ('submitted','reviewing')").first(),
        env.DB.prepare("SELECT COUNT(*) AS total FROM loan_applications WHERE status='approved'").first()
      ]);
      return json({ customers: customers.total, applications: applications.total, pending: pending.total, approved: approved.total });
    }
    if (path === "/api/admin/loans" && method === "GET") {
      const { results } = await env.DB.prepare("SELECT l.*,c.full_name,c.phone,c.email FROM loan_applications l JOIN customers c ON c.id=l.customer_id ORDER BY l.created_at DESC LIMIT 200").all();
      return json({ applications: results || [] });
    }
    const match = path.match(/^\\/api\\/admin\\/loans\\/(\\d+)$/);
    if (match && method === "PATCH") {
      let b; try { b = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
      const status = String(b.status || ""), note = String(b.adminNote || "").slice(0, 1000);
      if (!["reviewing","approved","declined","closed"].includes(status)) return json({ error: "Invalid application status." }, 422);
      const id = Number(match[1]);
      const exists = await env.DB.prepare("SELECT id FROM loan_applications WHERE id=?").bind(id).first();
      if (!exists) return json({ error: "Application not found." }, 404);
      await env.DB.prepare("UPDATE loan_applications SET status=?,admin_note=?,updated_at=datetime('now') WHERE id=?").bind(status, note, id).run();
      await audit(env, user, "loan.status_changed", "loan_application", id, { status });
      return json({ ok: true });
    }
    if (path === "/api/admin/repayments" && method === "POST") {
      let b; try { b = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
      const applicationId = Number(b.applicationId), amount = Number(b.amount), reference = String(b.reference || "").slice(0, 100), note = String(b.note || "").slice(0, 500);
      const loan = await env.DB.prepare("SELECT id,status FROM loan_applications WHERE id=?").bind(applicationId).first();
      if (!loan || loan.status !== "approved" || !Number.isSafeInteger(amount) || amount < 1 || amount > 100000000) return json({ error: "Check the approved application and repayment amount." }, 422);
      await env.DB.prepare("INSERT INTO repayments(application_id,amount_ugx,reference,recorded_by,note) VALUES(?,?,?,?,?)").bind(applicationId, amount, reference || null, user.id, note).run();
      await audit(env, user, "repayment.recorded", "loan_application", applicationId, { amount });
      return json({ ok: true }, 201);
    }
    return json({ error: "Admin API route not found." }, 404);
  }
  if (path === "/api/enquiries" && method === "POST") {
    let body; try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
    const name = String(body.name || "").trim(), phone = String(body.phone || "").trim(), email = String(body.email || "").trim();
    const type = body.type === "loan" ? "loan" : "account";
    if (name.length < 2 || name.length > 120 || !validPhone(phone)) return json({ error: "Enter a valid name and phone number." }, 422);
    if (email.length > 254 || (email && !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email))) return json({ error: "Enter a valid email address." }, 422);
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
  return json({ error: "API route not found." }, 404);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try { return await handleApi(request, env); }
      catch (error) { return json({ error: "The service could not complete this request." }, 500); }
    }
    return env.ASSETS.fetch(request);
  }
};
