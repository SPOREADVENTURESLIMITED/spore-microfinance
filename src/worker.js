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
  const match = raw.match(/(?:^|;\s*)spore_session=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
};
async function currentUser(request, env) {
  const token = cookieToken(request);
  if (!token || !env.DB) return null;
  const row = await env.DB.prepare("SELECT c.id,c.full_name,c.phone,c.email,c.role FROM sessions s JOIN customers c ON c.id=s.customer_id WHERE s.token_hash=? AND s.expires_at > datetime('now')").bind(await digest(token)).first();
  return row || null;
}
const sessionCookie = (token, maxAge = 604800) => `spore_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const validPhone = (v) => /^\+?[0-9 ()-]{7,24}$/.test(v);
const safeUser = (u) => ({ id: u.id, fullName: u.full_name, phone: u.phone, email: u.email, role: u.role });
async function audit(env, actor, action, entityType, entityId, details = {}) {
  await env.DB.prepare("INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?)")
    .bind(actor?.id || null, action, entityType, entityId || null, JSON.stringify(details)).run();
}

function addMonthsISO(dateText, months) {
  const d = new Date(dateText + "T00:00:00Z");
  const day = d.getUTCDate();
  d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() + months);
  const last = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
  d.setUTCDate(Math.min(day, last));
  return d.toISOString().slice(0, 10);
}
async function createLoanSchedule(env, loan, admin, body = {}) {
  const existing = await env.DB.prepare("SELECT id FROM loan_terms WHERE application_id=?").bind(loan.id).first();
  if (existing) return;
  const principal = Number(loan.amount_ugx), months = Number(loan.term_months);
  const rate = Number(body.monthlyRateBps ?? 200);
  const start = /^\d{4}-\d{2}-\d{2}$/.test(String(body.disbursementDate || "")) ? body.disbursementDate : new Date().toISOString().slice(0,10);
  const first = /^\d{4}-\d{2}-\d{2}$/.test(String(body.firstDueDate || "")) ? body.firstDueDate : addMonthsISO(start, 1);
  if (!Number.isInteger(rate) || rate < 0 || rate > 10000) throw new Error("Monthly interest rate must be 0 to 100 percent in basis points.");
  const r = rate / 10000;
  const payment = r === 0 ? Math.ceil(principal / months) : Math.ceil(principal * r / (1 - Math.pow(1 + r, -months)));
  let balance = principal, totalInterest = 0;
  const rows = [];
  for (let i = 1; i <= months; i++) {
    const interest = Math.round(balance * r);
    let principalDue = i === months ? balance : Math.min(balance, payment - interest);
    if (principalDue < 0) principalDue = 0;
    balance -= principalDue; totalInterest += interest;
    rows.push({i,due:addMonthsISO(first, i-1),principal:principalDue,interest,amount:principalDue+interest});
  }
  await env.DB.prepare("INSERT INTO loan_terms(application_id,principal_ugx,monthly_rate_bps,total_interest_ugx,total_payable_ugx,disbursement_date,first_due_date,created_by) VALUES(?,?,?,?,?,?,?,?)")
    .bind(loan.id, principal, rate, totalInterest, principal+totalInterest, start, first, admin.id).run();
  for (const x of rows) await env.DB.prepare("INSERT INTO repayment_schedule(application_id,installment_no,due_date,principal_due_ugx,interest_due_ugx,amount_due_ugx) VALUES(?,?,?,?,?,?)")
    .bind(loan.id,x.i,x.due,x.principal,x.interest,x.amount).run();
}

async function handleApi(request, env) {
  const url = new URL(request.url), path = url.pathname, method = request.method;
  if (!env.DB) return json({ error: "Database is not configured." }, 503);
  if (path === "/api/health" && method === "GET") return json({ ok: true, service: "Spore Microfinance API", databaseConfigured: true });
  if (path === "/api/auth/register" && method === "POST") {
    let b; try { b = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
    const name = String(b.fullName || "").trim(), phone = String(b.phone || "").trim(), email = String(b.email || "").trim().toLowerCase(), password = String(b.password || "");
    if (name.length < 2 || name.length > 120 || !validPhone(phone)) return json({ error: "Enter a valid full name and phone number." }, 422);
    if (email.length > 254 || (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return json({ error: "Enter a valid email address." }, 422);
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
    const kyc = await env.DB.prepare("SELECT status FROM kyc_profiles WHERE customer_id=?").bind(user.id).first();
    if (!kyc || kyc.status !== "verified") return json({ error: "Complete KYC and wait for administrator verification before submitting a loan application." }, 403);
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

  if (path === "/api/kyc" && method === "GET") {
    if (!user) return json({ error: "Please sign in." }, 401);
    const profile = await env.DB.prepare("SELECT id,date_of_birth,residential_address,district,occupation,document_type,document_last4,status,review_note,submitted_at,reviewed_at FROM kyc_profiles WHERE customer_id=?").bind(user.id).first();
    return json({ profile: profile || null });
  }
  if (path === "/api/kyc" && method === "POST") {
    if (!user) return json({ error: "Please sign in." }, 401);
    let b; try { b = await request.json(); } catch { return json({error:"Invalid request body."},400); }
    const dob=String(b.dateOfBirth||""), address=String(b.address||"").trim(), district=String(b.district||"").trim(), occupation=String(b.occupation||"").trim();
    const type=String(b.documentType||""), last4=String(b.documentLast4||"").replace(/\D/g,"");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dob) || dob >= new Date().toISOString().slice(0,10) || address.length<5 || address.length>250 || district.length<2 || district.length>80 || occupation.length<2 || occupation.length>100 || !["national_id","passport","driving_permit","voter_card"].includes(type) || !/^\d{4}$/.test(last4)) return json({error:"Complete all KYC fields with valid details. Enter only the last four document characters."},422);
    await env.DB.prepare("INSERT INTO kyc_profiles(customer_id,date_of_birth,residential_address,district,occupation,document_type,document_last4,status,review_note,submitted_at,reviewed_at) VALUES(?,?,?,?,?,?,?,'submitted','',datetime('now'),NULL) ON CONFLICT(customer_id) DO UPDATE SET date_of_birth=excluded.date_of_birth,residential_address=excluded.residential_address,district=excluded.district,occupation=excluded.occupation,document_type=excluded.document_type,document_last4=excluded.document_last4,status='submitted',review_note='',submitted_at=datetime('now'),reviewed_at=NULL")
      .bind(user.id,dob,address,district,occupation,type,last4).run();
    await audit(env,user,"kyc.submitted","kyc_profile",user.id,{documentType:type});
    return json({ok:true,message:"KYC details submitted for manual review."},201);
  }
  if (path === "/api/my/schedules" && method === "GET") {
    if (!user) return json({error:"Please sign in."},401);
    const {results}=await env.DB.prepare("SELECT s.*,l.amount_ugx,l.purpose,t.monthly_rate_bps FROM repayment_schedule s JOIN loan_applications l ON l.id=s.application_id JOIN loan_terms t ON t.application_id=l.id WHERE l.customer_id=? ORDER BY s.due_date,s.installment_no").bind(user.id).all();
    return json({schedules:results||[]});
  }

  if (path.startsWith("/api/admin/")) {
    if (!user) return json({ error: "Please sign in." }, 401);
    if (user.role !== "admin") return json({ error: "Administrator access required." }, 403);

    if (path === "/api/admin/kyc" && method === "GET") {
      const {results}=await env.DB.prepare("SELECT k.*,c.full_name,c.phone,c.email FROM kyc_profiles k JOIN customers c ON c.id=k.customer_id ORDER BY CASE k.status WHEN 'submitted' THEN 0 WHEN 'reviewing' THEN 1 ELSE 2 END,k.submitted_at DESC LIMIT 300").all();
      return json({profiles:results||[]});
    }
    const kycMatch=path.match(/^\/api\/admin\/kyc\/(\d+)$/);
    if (kycMatch && method === "PATCH") {
      let b; try { b=await request.json(); } catch { return json({error:"Invalid request body."},400); }
      const status=String(b.status||""), note=String(b.reviewNote||"").slice(0,1000), id=Number(kycMatch[1]);
      if (!["reviewing","verified","rejected"].includes(status)) return json({error:"Invalid KYC status."},422);
      const exists=await env.DB.prepare("SELECT id FROM kyc_profiles WHERE id=?").bind(id).first();
      if (!exists) return json({error:"KYC record not found."},404);
      await env.DB.prepare("UPDATE kyc_profiles SET status=?,reviewer_id=?,review_note=?,reviewed_at=CASE WHEN ? IN ('verified','rejected') THEN datetime('now') ELSE NULL END WHERE id=?").bind(status,user.id,note,status,id).run();
      await audit(env,user,"kyc.status_changed","kyc_profile",id,{status});
      return json({ok:true});
    }
    if (path === "/api/admin/reports" && method === "GET") {
      const from=String(url.searchParams.get("from")||"2000-01-01"), to=String(url.searchParams.get("to")||"2999-12-31");
      if (!/^\d{4}-\d{2}-\d{2}$/.test(from) || !/^\d{4}-\d{2}-\d{2}$/.test(to) || from>to) return json({error:"Invalid reporting date range."},422);
      const [portfolio,collections,overdue,byStatus,monthly]=await Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS active_loans,COALESCE(SUM(t.principal_ugx),0) AS principal_booked,COALESCE(SUM(t.total_payable_ugx),0) AS total_contractual,COALESCE(SUM(t.total_payable_ugx-(SELECT COALESCE(SUM(r.amount_ugx),0) FROM repayments r WHERE r.application_id=t.application_id)),0) AS outstanding FROM loan_terms t JOIN loan_applications l ON l.id=t.application_id WHERE l.status='approved'").first(),
        env.DB.prepare("SELECT COUNT(*) AS payment_count,COALESCE(SUM(amount_ugx),0) AS collected FROM repayments WHERE date(paid_at) BETWEEN ? AND ?").bind(from,to).first(),
        env.DB.prepare("SELECT COUNT(*) AS overdue_installments,COALESCE(SUM(amount_due_ugx-principal_paid_ugx-interest_paid_ugx),0) AS overdue_amount FROM repayment_schedule WHERE due_date<? AND status!='paid'").bind(new Date().toISOString().slice(0,10)).first(),
        env.DB.prepare("SELECT status,COUNT(*) AS total FROM loan_applications GROUP BY status").all(),
        env.DB.prepare("SELECT substr(paid_at,1,7) AS month,COALESCE(SUM(amount_ugx),0) AS collected,COUNT(*) AS payments FROM repayments WHERE date(paid_at) BETWEEN ? AND ? GROUP BY substr(paid_at,1,7) ORDER BY month").bind(from,to).all()
      ]);
      return json({from,to,portfolio,collections,overdue,applicationsByStatus:byStatus.results||[],monthlyCollections:monthly.results||[]});
    }
    if (path === "/api/admin/schedules" && method === "GET") {
      const {results}=await env.DB.prepare("SELECT s.*,l.amount_ugx,l.customer_id,c.full_name,c.phone FROM repayment_schedule s JOIN loan_applications l ON l.id=s.application_id JOIN customers c ON c.id=l.customer_id ORDER BY s.due_date LIMIT 1000").all();
      return json({schedules:results||[]});
    }

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
    const match = path.match(/^\/api\/admin\/loans\/(\d+)$/);
    if (match && method === "PATCH") {
      let b; try { b = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
      const status = String(b.status || ""), note = String(b.adminNote || "").slice(0, 1000);
      if (!["reviewing","approved","declined","closed"].includes(status)) return json({ error: "Invalid application status." }, 422);
      const id = Number(match[1]);
      const exists = await env.DB.prepare("SELECT id FROM loan_applications WHERE id=?").bind(id).first();
      if (!exists) return json({ error: "Application not found." }, 404);
      await env.DB.prepare("UPDATE loan_applications SET status=?,admin_note=?,updated_at=datetime('now') WHERE id=?").bind(status, note, id).run();
      if (status === "approved") {
        const loan = await env.DB.prepare("SELECT id,amount_ugx,term_months FROM loan_applications WHERE id=?").bind(id).first();
        await createLoanSchedule(env, loan, user, b);
      }
      await audit(env, user, "loan.status_changed", "loan_application", id, { status });
      return json({ ok: true });
    }
    if (path === "/api/admin/repayments" && method === "POST") {
      let b; try { b = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
      const applicationId = Number(b.applicationId), amount = Number(b.amount), reference = String(b.reference || "").slice(0, 100), note = String(b.note || "").slice(0, 500);
      const loan = await env.DB.prepare("SELECT id,status FROM loan_applications WHERE id=?").bind(applicationId).first();
      if (!loan || loan.status !== "approved" || !Number.isSafeInteger(amount) || amount < 1 || amount > 100000000) return json({ error: "Check the approved application and repayment amount." }, 422);
      const terms=await env.DB.prepare("SELECT total_payable_ugx FROM loan_terms WHERE application_id=?").bind(applicationId).first();
      if (!terms) return json({error:"Set approved loan terms before recording repayments."},409);
      const paid=await env.DB.prepare("SELECT COALESCE(SUM(amount_ugx),0) AS total FROM repayments WHERE application_id=?").bind(applicationId).first();
      const outstanding=terms.total_payable_ugx-paid.total;
      if (amount>outstanding) return json({error:"Payment exceeds the outstanding loan balance of UGX "+outstanding+"."},422);
      const saved=await env.DB.prepare("INSERT INTO repayments(application_id,amount_ugx,reference,recorded_by,note) VALUES(?,?,?,?,?)").bind(applicationId,amount,reference||null,user.id,note).run();
      let remaining=amount;
      const {results:dueRows}=await env.DB.prepare("SELECT * FROM repayment_schedule WHERE application_id=? AND status!='paid' ORDER BY due_date,installment_no").bind(applicationId).all();
      for (const row of dueRows||[]) {
        if (remaining<=0) break;
        const interestLeft=row.interest_due_ugx-row.interest_paid_ugx;
        const principalLeft=row.principal_due_ugx-row.principal_paid_ugx;
        const interestPart=Math.min(remaining,interestLeft); remaining-=interestPart;
        const principalPart=Math.min(remaining,principalLeft); remaining-=principalPart;
        if (interestPart+principalPart>0) {
          await env.DB.prepare("INSERT INTO repayment_allocations(repayment_id,schedule_id,principal_ugx,interest_ugx) VALUES(?,?,?,?)").bind(saved.meta.last_row_id,row.id,principalPart,interestPart).run();
          const nextInterest=row.interest_paid_ugx+interestPart, nextPrincipal=row.principal_paid_ugx+principalPart;
          const status=(nextInterest>=row.interest_due_ugx && nextPrincipal>=row.principal_due_ugx)?"paid":"partial";
          await env.DB.prepare("UPDATE repayment_schedule SET interest_paid_ugx=?,principal_paid_ugx=?,status=?,paid_at=CASE WHEN ?='paid' THEN datetime('now') ELSE paid_at END WHERE id=?").bind(nextInterest,nextPrincipal,status,status,row.id).run();
        }
      }
      await audit(env,user,"repayment.recorded","loan_application",applicationId,{amount,reference:reference||null});
      return json({ok:true,allocated:amount-remaining,outstanding:outstanding-amount},201);
    }
    return json({ error: "Admin API route not found." }, 404);
  }
  if (path === "/api/enquiries" && method === "POST") {
    let body; try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
    const name = String(body.name || "").trim(), phone = String(body.phone || "").trim(), email = String(body.email || "").trim();
    const type = body.type === "loan" ? "loan" : "account";
    if (name.length < 2 || name.length > 120 || !validPhone(phone)) return json({ error: "Enter a valid name and phone number." }, 422);
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
