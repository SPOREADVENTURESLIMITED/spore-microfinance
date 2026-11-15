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
  const row = await env.DB.prepare("SELECT c.id,c.full_name,c.phone,c.email,c.role,c.admin_totp_enabled,s.mfa_verified FROM sessions s JOIN customers c ON c.id=s.customer_id WHERE s.token_hash=? AND s.expires_at > datetime('now')").bind(await digest(token)).first();
  return row || null;
}
const sessionCookie = (token, maxAge = 604800) => `spore_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const B32="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(bytes){let bits=0,value=0,out="";for(const byte of bytes){value=(value<<8)|byte;bits+=8;while(bits>=5){out+=B32[(value>>>(bits-5))&31];bits-=5;}}if(bits)out+=B32[(value<<(5-bits))&31];return out;}
function base32Decode(input){const clean=String(input||"").toUpperCase().replace(/=+$/,"").replace(/[^A-Z2-7]/g,"");let bits=0,value=0,out=[];for(const ch of clean){const n=B32.indexOf(ch);if(n<0)throw new Error("Invalid authenticator secret.");value=(value<<5)|n;bits+=5;if(bits>=8){out.push((value>>>(bits-8))&255);bits-=8;}}return new Uint8Array(out);}
async function totpCode(secret,stepOffset=0){const counter=Math.floor(Date.now()/30000)+stepOffset;const msg=new Uint8Array(8);let n=counter;for(let i=7;i>=0;i--){msg[i]=n&255;n=Math.floor(n/256);}const key=await crypto.subtle.importKey("raw",base32Decode(secret),{name:"HMAC",hash:"SHA-1"},false,["sign"]);const mac=new Uint8Array(await crypto.subtle.sign("HMAC",key,msg));const off=mac[mac.length-1]&15;const bin=((mac[off]&127)<<24)|(mac[off+1]<<16)|(mac[off+2]<<8)|mac[off+3];return String(bin%1000000).padStart(6,"0");}
async function verifyTotp(secret,code){for(const offset of [-1,0,1])if(await totpCode(secret,offset)===String(code))return true;return false;}
async function verifyRecoveryCode(env,userId,code){const hash=await digest("spore-admin-recovery:"+userId+":"+String(code).replace(/[^a-f0-9]/gi,"").toLowerCase());const row=await env.DB.prepare("SELECT id FROM admin_mfa_recovery_codes WHERE customer_id=? AND code_hash=? AND used_at IS NULL").bind(userId,hash).first();if(!row)return false;await env.DB.prepare("UPDATE admin_mfa_recovery_codes SET used_at=datetime('now') WHERE id=? AND used_at IS NULL").bind(row.id).run();return true;}
async function makeRecoveryCodes(env,userId){const codes=Array.from({length:10},()=>randomHex(8).toUpperCase());const stmts=[env.DB.prepare("DELETE FROM admin_mfa_recovery_codes WHERE customer_id=?").bind(userId)];for(const code of codes)stmts.push(env.DB.prepare("INSERT INTO admin_mfa_recovery_codes(customer_id,code_hash) VALUES(?,?)").bind(userId,await digest("spore-admin-recovery:"+userId+":"+code.toLowerCase())));await env.DB.batch(stmts);return codes;}
const validPhone = (v) => /^\+?[0-9 ()-]{7,24}$/.test(v);
const safeUser = (u) => ({ id: u.id, fullName: u.full_name, phone: u.phone, email: u.email, role: u.role });
async function sendSms(env, to, message) {
  const sid=String(env.SMS_ACCOUNT_SID||""), token=String(env.SMS_AUTH_TOKEN||""), from=String(env.SMS_FROM||"");
  if (!sid || !token || !from) throw new Error("SMS delivery is not configured.");
  const body=new URLSearchParams({To:to,From:from,Body:message});
  const response=await fetch("https://api.twilio.com/2010-04-01/Accounts/"+encodeURIComponent(sid)+"/Messages.json",{
    method:"POST",headers:{"authorization":"Basic "+btoa(sid+":"+token),"content-type":"application/x-www-form-urlencoded"},body
  });
  if (!response.ok) throw new Error("SMS provider rejected the message.");
}
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
  const principal = Number(loan.amount_ugx), months = Number(loan.term_months);
  const existing = await env.DB.prepare("SELECT id FROM loan_terms WHERE application_id=?").bind(loan.id).first();
  if (existing) {
    const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM repayment_schedule WHERE application_id=?").bind(loan.id).first();
    if (count.total === months) return;
    const paid = await env.DB.prepare("SELECT COUNT(*) AS total FROM repayments WHERE application_id=?").bind(loan.id).first();
    if (paid.total > 0) throw new Error("Existing repayment schedule is incomplete and already has payments; manual reconciliation is required.");
    await env.DB.batch([
      env.DB.prepare("DELETE FROM repayment_schedule WHERE application_id=?").bind(loan.id),
      env.DB.prepare("DELETE FROM loan_terms WHERE application_id=?").bind(loan.id)
    ]);
  }
  const rate = Number(body.monthlyRateBps ?? 200);
  const start = /^\d{4}-\d{2}-\d{2}$/.test(String(body.disbursementDate || "")) ? body.disbursementDate : new Date().toISOString().slice(0,10);
  const first = /^\d{4}-\d{2}-\d{2}$/.test(String(body.firstDueDate || "")) ? body.firstDueDate : addMonthsISO(start, 1);
  if (!Number.isSafeInteger(principal) || principal <= 0 || !Number.isInteger(months) || months <= 0) throw new Error("Loan principal or term is invalid.");
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
  const statements = [
    env.DB.prepare("INSERT INTO loan_terms(application_id,principal_ugx,monthly_rate_bps,total_interest_ugx,total_payable_ugx,disbursement_date,first_due_date,created_by) VALUES(?,?,?,?,?,?,?,?)")
      .bind(loan.id, principal, rate, totalInterest, principal+totalInterest, start, first, admin.id)
  ];
  for (const x of rows) statements.push(
    env.DB.prepare("INSERT INTO repayment_schedule(application_id,installment_no,due_date,principal_due_ugx,interest_due_ugx,amount_due_ugx) VALUES(?,?,?,?,?,?)")
      .bind(loan.id,x.i,x.due,x.principal,x.interest,x.amount)
  );
  await env.DB.batch(statements);
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
    if (!phone || phone.length > 24 || password.length > 128) return json({ error: "Phone number or password is incorrect." }, 401);
    await env.DB.prepare("DELETE FROM login_attempts WHERE attempted_at < datetime('now','-1 day')").run();
    const attempts = await env.DB.prepare("SELECT COUNT(*) AS total FROM login_attempts WHERE phone=? AND attempted_at > datetime('now','-15 minutes')").bind(phone).first();
    if (attempts.total >= 8) return json({ error: "Too many unsuccessful sign-in attempts. Please wait 15 minutes and try again." }, 429);
    const user = await env.DB.prepare("SELECT * FROM customers WHERE phone=?").bind(phone).first();
    if (!user || (await passwordHash(password, user.password_salt)) !== user.password_hash) {
      await env.DB.prepare("INSERT INTO login_attempts(phone) VALUES(?)").bind(phone).run();
      return json({ error: "Phone number or password is incorrect." }, 401);
    }
    await env.DB.prepare("DELETE FROM login_attempts WHERE phone=?").bind(phone).run();
    const token = randomHex(32);
    await env.DB.prepare("INSERT INTO sessions(customer_id,token_hash,expires_at,mfa_verified) VALUES(?,?,datetime('now','+7 days'),?)").bind(user.id, await digest(token), user.role === "admin" ? 0 : 1).run();
    return json({ ok: true, user: safeUser(user), mfaRequired: user.role === "admin", mfaSetupRequired: user.role === "admin" && Number(user.admin_totp_enabled) !== 1 }, 200, { "set-cookie": sessionCookie(token) });
  }
  if (path === "/api/auth/password/forgot" && method === "POST") {
    let b; try { b=await request.json(); } catch { return json({error:"Invalid request body."},400); }
    const phone=String(b.phone||"").trim();
    if (!validPhone(phone)) return json({error:"Enter the phone number registered to your account."},422);
    if (!env.RESET_CODE_PEPPER) return json({error:"Password recovery is not configured. Please contact support."},503);
    const recent=await env.DB.prepare("SELECT COUNT(*) AS total FROM password_resets WHERE phone=? AND created_at>datetime('now','-1 hour')").bind(phone).first();
    if (recent.total>=3) return json({error:"Too many reset requests. Try again in one hour."},429);
    const customer=await env.DB.prepare("SELECT id FROM customers WHERE phone=?").bind(phone).first();
    // Return the same response for known and unknown numbers to prevent account discovery.
    if (customer) {
      const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,"0");
      const codeHash=await digest(phone+":"+code+":"+env.RESET_CODE_PEPPER);
      await env.DB.prepare("INSERT INTO password_resets(phone,code_hash,expires_at) VALUES(?,?,datetime('now','+10 minutes'))").bind(phone,codeHash).run();
      try { await sendSms(env,phone,"Your Spore Microfinance password reset code is "+code+". It expires in 10 minutes. Do not share it."); }
      catch { await env.DB.prepare("DELETE FROM password_resets WHERE phone=?").bind(phone).run(); return json({error:"SMS delivery is temporarily unavailable. Please contact support."},503); }
    }
    return json({ok:true,message:"If the number is registered, a password reset code has been sent by SMS."});
  }
  if (path === "/api/auth/password/reset" && method === "POST") {
    let b; try { b=await request.json(); } catch { return json({error:"Invalid request body."},400); }
    const phone=String(b.phone||"").trim(), code=String(b.code||"").trim(), password=String(b.password||"");
    if (!validPhone(phone) || !/^\d{6}$/.test(code) || password.length<10 || password.length>128) return json({error:"Enter the registered phone, six-digit code and a password of 10–128 characters."},422);
    const reset=await env.DB.prepare("SELECT id,code_hash,attempts FROM password_resets WHERE phone=? AND expires_at>datetime('now') ORDER BY id DESC LIMIT 1").bind(phone).first();
    if (!reset || reset.attempts>=5 || await digest(phone+":"+code+":"+env.RESET_CODE_PEPPER)!==reset.code_hash) {
      if (reset) await env.DB.prepare("UPDATE password_resets SET attempts=attempts+1 WHERE id=?").bind(reset.id).run();
      return json({error:"The reset code is invalid or expired."},400);
    }
    const salt=randomHex(16), hash=await passwordHash(password,salt);
    const customer=await env.DB.prepare("SELECT id FROM customers WHERE phone=?").bind(phone).first();
    if (!customer) return json({error:"The reset code is invalid or expired."},400);
    await env.DB.batch([
      env.DB.prepare("UPDATE customers SET password_hash=?,password_salt=?,updated_at=datetime('now') WHERE id=?").bind(hash,salt,customer.id),
      env.DB.prepare("DELETE FROM sessions WHERE customer_id=?").bind(customer.id),
      env.DB.prepare("DELETE FROM password_resets WHERE phone=?").bind(phone),
      env.DB.prepare("INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?)").bind(customer.id,"customer.password_reset","customer",customer.id,"{}")
    ]);
    return json({ok:true,message:"Password reset successfully. Please sign in with your new password."});
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

  const verifyMatch = path.match(/^\/api\/verify\/(loan|schedule|payment)\/(\d+)$/);
  if (verifyMatch && method === "GET") {
    const kind = verifyMatch[1], id = Number(verifyMatch[2]);
    let record = null;
    if (kind === "loan") {
      record = await env.DB.prepare("SELECT l.id,l.status,l.amount_ugx,l.purpose,l.term_months,l.created_at,t.total_payable_ugx,t.monthly_rate_bps,t.disbursement_date FROM loan_applications l JOIN loan_terms t ON t.application_id=l.id WHERE l.id=? AND l.status='approved'").bind(id).first();
      if (record) record = { reference: "SPORE-LOAN-" + String(record.id).padStart(6,"0"), type: "Loan agreement record", status: "valid", applicationId: record.id, principal: record.amount_ugx, totalPayable: record.total_payable_ugx, termMonths: record.term_months, monthlyRateBps: record.monthly_rate_bps, disbursementDate: record.disbursement_date };
    } else if (kind === "schedule") {
      record = await env.DB.prepare("SELECT s.id,s.application_id,s.installment_no,s.due_date,s.amount_due_ugx,s.status,l.status AS loan_status,(SELECT COUNT(*) FROM repayment_schedule z WHERE z.application_id=s.application_id) AS total_installments FROM repayment_schedule s JOIN loan_applications l ON l.id=s.application_id WHERE s.application_id=? AND l.status='approved' ORDER BY s.installment_no LIMIT 1").bind(id).first();
      if (record) record = { reference: "SPORE-SCHEDULE-" + String(record.application_id).padStart(6,"0"), type: "Loan repayment schedule", status: "valid", applicationId: record.application_id, totalInstallments: record.total_installments, firstDueDate: record.due_date };
    } else {
      record = await env.DB.prepare("SELECT r.id,r.application_id,r.amount_ugx,r.reference,r.paid_at,l.status AS loan_status FROM repayments r JOIN loan_applications l ON l.id=r.application_id WHERE r.id=? AND l.status='approved'").bind(id).first();
      if (record) record = { reference: "SPORE-RECEIPT-" + String(record.id).padStart(6,"0"), type: "Payment receipt", status: "recorded", applicationId: record.application_id, amount: record.amount_ugx, paymentReference: record.reference || null, paidAt: record.paid_at, settlementNotice: "Recorded by an administrator; not independently confirmed by a payment provider." };
    }
    return record ? json({ verified: true, document: record }) : json({ verified: false, error: "Document reference not found or no longer valid." }, 404);
  }

    if (path === "/api/admin/mfa/setup" && method === "POST") {
    const user=await currentUser(request,env);
    if(!user||user.role!=="admin")return json({error:"Administrator sign-in required."},401);
    if(Number(user.admin_totp_enabled)===1)return json({error:"Authenticator MFA is already enabled."},409);
    let row=await env.DB.prepare("SELECT admin_totp_secret FROM customers WHERE id=?").bind(user.id).first();
    let secret=row?.admin_totp_secret;
    if(!secret){secret=base32Encode(crypto.getRandomValues(new Uint8Array(20)));await env.DB.prepare("UPDATE customers SET admin_totp_secret=? WHERE id=? AND admin_totp_enabled=0").bind(secret,user.id).run();}
    const issuer="SPORE%20Microfinance",label=encodeURIComponent("SPORE Microfinance:"+user.phone);
    return json({ok:true,secret,otpauthUri:"otpauth://totp/"+label+"?secret="+secret+"&issuer="+issuer+"&algorithm=SHA1&digits=6&period=30"});
  }
  if (path === "/api/admin/mfa/confirm" && method === "POST") {
    const user=await currentUser(request,env);
    if(!user||user.role!=="admin"||Number(user.admin_totp_enabled)===1)return json({error:"Administrator MFA setup is not available."},403);
    let b;try{b=await request.json()}catch{return json({error:"Invalid request body."},400)}
    const row=await env.DB.prepare("SELECT admin_totp_secret FROM customers WHERE id=?").bind(user.id).first();
    if(!row?.admin_totp_secret||!await verifyTotp(row.admin_totp_secret,String(b.code||"")))return json({error:"Authenticator code is incorrect. Check your device time and try again."},400);
    await env.DB.batch([
      env.DB.prepare("UPDATE customers SET admin_totp_enabled=1,updated_at=datetime('now') WHERE id=?").bind(user.id),
      env.DB.prepare("UPDATE sessions SET mfa_verified=1 WHERE token_hash=?").bind(await digest(cookieToken(request))),
      env.DB.prepare("INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?)").bind(user.id,"admin.mfa_enabled","customer",user.id,"{}")
    ]);
    const recoveryCodes=await makeRecoveryCodes(env,user.id);
    return json({ok:true,recoveryCodes,message:"Authenticator MFA enabled. Save these one-time recovery codes now."});
  }
  if (path === "/api/auth/mfa/verify" && method === "POST") {
    const user=await currentUser(request,env);
    if(!user||user.role!=="admin"||Number(user.admin_totp_enabled)!==1)return json({error:"Administrator MFA challenge is not available."},403);
    let b;try{b=await request.json()}catch{return json({error:"Invalid request body."},400)}
    const row=await env.DB.prepare("SELECT admin_totp_secret FROM customers WHERE id=?").bind(user.id).first();
    const code=String(b.code||"").trim();
    let valid=!!row?.admin_totp_secret&&await verifyTotp(row.admin_totp_secret,code);
    if(!valid)valid=await verifyRecoveryCode(env,user.id,code);
    if(!valid)return json({error:"Authenticator or recovery code is invalid."},400);
    await env.DB.prepare("UPDATE sessions SET mfa_verified=1 WHERE token_hash=?").bind(await digest(cookieToken(request))).run();
    await audit(env,user,"admin.mfa_verified","customer",user.id);
    return json({ok:true,message:"Administrator verification successful."});
  }

  const user = await currentUser(request, env);
  if (path === "/api/me" && method === "GET") return user ? json({ user: safeUser(user), mfaVerified: user.role !== "admin" || Number(user.mfa_verified) === 1, mfaSetupRequired: user.role === "admin" && Number(user.admin_totp_enabled) !== 1 }) : json({ error: "Please sign in." }, 401);
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
    const type=String(b.documentType||""), last4=String(b.documentLast4||"").trim().toUpperCase();
    const adultCutoff=new Date(); adultCutoff.setUTCFullYear(adultCutoff.getUTCFullYear()-18); if (!/^\d{4}-\d{2}-\d{2}$/.test(dob) || dob > adultCutoff.toISOString().slice(0,10) || address.length<5 || address.length>250 || district.length<2 || district.length>80 || occupation.length<2 || occupation.length>100 || !["national_id","passport","driving_permit","voter_card"].includes(type) || !/^[A-Z0-9]{4}$/.test(last4)) return json({error:"Complete all KYC fields with valid details. Enter only the last four document characters."},422);
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


  if (path === "/api/my/documents" && method === "GET") {
    if (!user) return json({ error: "Please sign in." }, 401);
    const [loans,schedules,payments] = await Promise.all([
      env.DB.prepare("SELECT l.id,l.amount_ugx,l.purpose,l.term_months,l.status,l.created_at,t.principal_ugx,t.monthly_rate_bps,t.total_interest_ugx,t.total_payable_ugx,t.disbursement_date,t.first_due_date FROM loan_applications l JOIN loan_terms t ON t.application_id=l.id WHERE l.customer_id=? AND l.status='approved' ORDER BY l.id DESC").bind(user.id).all(),
      env.DB.prepare("SELECT s.id,s.application_id,s.installment_no,s.due_date,s.principal_due_ugx,s.interest_due_ugx,s.amount_due_ugx,s.principal_paid_ugx,s.interest_paid_ugx,s.status FROM repayment_schedule s JOIN loan_applications l ON l.id=s.application_id WHERE l.customer_id=? AND l.status='approved' ORDER BY s.application_id,s.installment_no").bind(user.id).all(),
      env.DB.prepare("SELECT r.id,r.application_id,r.amount_ugx,r.reference,r.paid_at,l.purpose FROM repayments r JOIN loan_applications l ON l.id=r.application_id WHERE l.customer_id=? AND l.status='approved' ORDER BY r.paid_at DESC").bind(user.id).all()
    ]);
    return json({ loans: loans.results || [], schedules: schedules.results || [], payments: payments.results || [] });
  }

  if (path.startsWith("/api/admin/")) {
    if (!user) return json({ error: "Please sign in." }, 401);
    if (user.role !== "admin") return json({ error: "Administrator access required." }, 403);
    if (Number(user.mfa_verified) !== 1) return json({ error: "Complete administrator authenticator verification first." }, 428);

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
      const exists = await env.DB.prepare("SELECT id,customer_id,status FROM loan_applications WHERE id=?").bind(id).first();
      if (!exists) return json({ error: "Application not found." }, 404);
      if (status === "approved") {
        const kyc = await env.DB.prepare("SELECT status FROM kyc_profiles WHERE customer_id=?").bind(exists.customer_id).first();
        if (!kyc || kyc.status !== "verified") return json({ error: "Loan approval is blocked until the customer's KYC is verified." }, 409);
      }
      if (status === "approved" && exists.status === "approved") return json({ error: "This loan is already approved." }, 409);
      // Build the complete schedule before changing the application to approved.
      // Schedule rows and loan terms are committed together by D1 batch.
      if (status === "approved") {
        const loan = await env.DB.prepare("SELECT id,amount_ugx,term_months FROM loan_applications WHERE id=?").bind(id).first();
        await createLoanSchedule(env, loan, user, b);
      }
      await env.DB.prepare("UPDATE loan_applications SET status=?,admin_note=?,updated_at=datetime('now') WHERE id=?").bind(status, note, id).run();
      await audit(env, user, "loan.status_changed", "loan_application", id, { status });
      return json({ ok: true });
    }
    if (path === "/api/admin/repayments" && method === "POST") {
      let b; try { b = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
      const applicationId = Number(b.applicationId), amount = Number(b.amount), reference = String(b.reference || "").slice(0, 100), note = String(b.note || "").slice(0, 500);
      const loan = await env.DB.prepare("SELECT id,status,payment_version FROM loan_applications WHERE id=?").bind(applicationId).first();
      if (!loan || loan.status !== "approved" || !Number.isSafeInteger(amount) || amount < 1 || amount > 100000000) return json({ error: "Check the approved application and repayment amount." }, 422);
      const terms=await env.DB.prepare("SELECT total_payable_ugx FROM loan_terms WHERE application_id=?").bind(applicationId).first();
      if (!terms) return json({error:"Set approved loan terms before recording repayments."},409);
      const paid=await env.DB.prepare("SELECT COALESCE(SUM(amount_ugx),0) AS total FROM repayments WHERE application_id=?").bind(applicationId).first();
      const outstanding=terms.total_payable_ugx-paid.total;
      if (amount>outstanding) return json({error:"Payment exceeds the outstanding loan balance of UGX "+outstanding+"."},422);
      const {results:dueRows}=await env.DB.prepare("SELECT * FROM repayment_schedule WHERE application_id=? AND status!='paid' ORDER BY due_date,installment_no").bind(applicationId).all();
      let remaining=amount;
      const statements = [
        env.DB.prepare("UPDATE loan_applications SET payment_version=payment_version+1 WHERE id=? AND payment_version=? AND status='approved'").bind(applicationId,Number(loan.payment_version||0)),
        env.DB.prepare("INSERT INTO payment_assertions(ok) VALUES(changes())"),
        env.DB.prepare("INSERT INTO repayments(application_id,amount_ugx,reference,recorded_by,note) VALUES(?,?,?,?,?)").bind(applicationId,amount,reference||null,user.id,note)
      ];
      let allocated=0;
      for (const row of dueRows||[]) {
        if (remaining<=0) break;
        const interestLeft=row.interest_due_ugx-row.interest_paid_ugx;
        const principalLeft=row.principal_due_ugx-row.principal_paid_ugx;
        const interestPart=Math.min(remaining,interestLeft); remaining-=interestPart;
        const principalPart=Math.min(remaining,principalLeft); remaining-=principalPart;
        if (interestPart+principalPart>0) {
          allocated+=interestPart+principalPart;
          statements.push(env.DB.prepare("INSERT INTO repayment_allocations(repayment_id,schedule_id,principal_ugx,interest_ugx) SELECT id,?,?,? FROM repayments WHERE application_id=? ORDER BY id DESC LIMIT 1").bind(row.id,principalPart,interestPart,applicationId));
          const nextInterest=row.interest_paid_ugx+interestPart, nextPrincipal=row.principal_paid_ugx+principalPart;
          const status=(nextInterest>=row.interest_due_ugx && nextPrincipal>=row.principal_due_ugx)?"paid":"partial";
          statements.push(env.DB.prepare("UPDATE repayment_schedule SET interest_paid_ugx=?,principal_paid_ugx=?,status=?,paid_at=CASE WHEN ?='paid' THEN datetime('now') ELSE paid_at END WHERE id=?").bind(nextInterest,nextPrincipal,status,status,row.id));
        }
      }
      if (remaining!==0 || allocated!==amount) return json({error:"The repayment could not be fully allocated to the remaining schedule. No payment was recorded."},409);
      statements.push(env.DB.prepare("INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?)").bind(user.id,"repayment.recorded","loan_application",applicationId,JSON.stringify({amount,reference:reference||null})));
      // D1 batch executes these statements in one transaction, preventing partial payment/allocation writes.
      statements.push(env.DB.prepare("DELETE FROM payment_assertions"));
      let batchResult;
      try { batchResult=await env.DB.batch(statements); }
      catch(error) {
        const latest=await env.DB.prepare("SELECT payment_version FROM loan_applications WHERE id=?").bind(applicationId).first();
        if(latest && Number(latest.payment_version)!==Number(loan.payment_version||0))return json({error:"Another repayment was recorded at the same time. Refresh the loan balance and retry."},409);
        throw error;
      }
      const repaymentId=batchResult[2]?.meta?.last_row_id;
      return json({ok:true,repaymentId,applicationId,amount,reference:reference||null,paidAt:new Date().toISOString(),allocated:amount-remaining,outstanding:outstanding-amount},201);
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
