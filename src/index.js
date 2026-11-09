
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return [...new Uint8Array(digest)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}
async function createAdminSession(password) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const expires = Math.floor(Date.now() / 1000) + 8 * 60 * 60;
  const payload = String(expires);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload)
  );

  const signatureHex = [...new Uint8Array(signature)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  return `${payload}.${signatureHex}`;
}

async function verifyAdminSession(request, password) {
  if (!password) return false;

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)asq_admin_session=([^;]+)/);

  if (!match) return false;

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  const expires = Number(parts[0]);
  if (!Number.isFinite(expires) || expires < Math.floor(Date.now() / 1000)) {
    return false;
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signature = new Uint8Array(
    (parts[1].match(/.{2}/g) || []).map(byte => parseInt(byte, 16))
  );

  if (signature.length !== 32) return false;

  return crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    encoder.encode(parts[0])
  );
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    try {
      // Admin login
if (url.pathname === "/api/admin/login" && method === "POST") {
  if (!env.ADMIN_PASSWORD) {
    return json({ error: "Admin password is not configured." }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid request." }, 400);
  }

  const submitted = String(body.password || "");

  if (submitted.length > 200 || submitted !== env.ADMIN_PASSWORD) {
    return json({ error: "Incorrect admin password." }, 401);
  }

  const session = await createAdminSession(env.ADMIN_PASSWORD);

  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "set-cookie": `asq_admin_session=${session}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`
    }
  });
}

// Check admin session
if (url.pathname === "/api/admin/session" && method === "GET") {
  const authenticated = await verifyAdminSession(
    request,
    env.ADMIN_PASSWORD
  );

  return json({ authenticated });
}

// Admin logout
if (url.pathname === "/api/admin/logout" && method === "POST") {
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "set-cookie": "asq_admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
    }
  });
}
      // Test database connection
      if (url.pathname === "/api/health" && method === "GET") {
        if (!env.DB) {
          return json({ ok: false, error: "D1 binding DB is missing." }, 500);
        }

        await env.DB.prepare("SELECT 1 AS connected").first();

        return json({
          ok: true,
          database: "connected"
        });
      }

      // Load published mock examinations
      if (url.pathname === "/api/mocks" && method === "GET") {
        if (!env.DB) {
          return json({ error: "Database is not configured." }, 500);
        }

        const result = await env.DB.prepare(`
          SELECT id, title, subjects_json, duration_minutes, question_count
          FROM mocks
          WHERE status = 'published'
            AND (available_from IS NULL OR available_from <= datetime('now'))
            AND (available_until IS NULL OR available_until >= datetime('now'))
          ORDER BY created_at DESC
        `).all();

        const mocks = (result.results || []).map(mock => ({
          id: mock.id,
          title: mock.title,
          subjects: JSON.parse(mock.subjects_json || "[]"),
          durationMinutes: mock.duration_minutes,
          questionCount: mock.question_count
        }));

        return json({ mocks });
      }

      // Redeem a one-time access code
      if (url.pathname === "/api/redeem-code" && method === "POST") {
        if (!env.DB) {
          return json({ error: "Database is not configured." }, 500);
        }

        let body;

        try {
          body = await request.json();
        } catch {
          return json({ error: "Please submit valid form details." }, 400);
        }

        const fullName = String(body.fullName || "")
          .trim()
          .replace(/\s+/g, " ");

        const accessCode = String(body.accessCode || "")
          .trim()
          .toUpperCase();

        const mockId = String(body.mockId || "").trim();

        if (
          fullName.length < 3 ||
          fullName.length > 100 ||
          !/^[A-Z0-9-]{6,40}$/.test(accessCode) ||
          mockId.length < 1 ||
          mockId.length > 80
        ) {
          return json({
            error: "Enter your full name, access code and select a mock."
          }, 400);
        }

        const mock = await env.DB.prepare(`
          SELECT id FROM mocks
          WHERE id = ?
            AND status = 'published'
            AND (available_from IS NULL OR available_from <= datetime('now'))
            AND (available_until IS NULL OR available_until >= datetime('now'))
        `).bind(mockId).first();

        if (!mock) {
          return json({
            error: "This mock is not currently available."
          }, 404);
        }

        const codeHash = await sha256(accessCode);
        const now = new Date().toISOString();
        const studentId = crypto.randomUUID();
        const attemptId = crypto.randomUUID();

        // D1 batch executes these statements transactionally.
        const results = await env.DB.batch([
          // Create student only if the code is valid and unused.
          env.DB.prepare(`
            INSERT INTO students (id, full_name, created_at)
            SELECT ?, ?, ?
            WHERE EXISTS (
              SELECT 1 FROM access_codes
              WHERE code_hash = ?
                AND is_active = 1
                AND redeemed_at IS NULL
            )
            AND EXISTS (
              SELECT 1 FROM mocks
              WHERE id = ? AND status = 'published'
            )
          `).bind(
            studentId,
            fullName,
            now,
            codeHash,
            mockId
          ),

          // Permanently redeem the code.
          env.DB.prepare(`
            UPDATE access_codes
            SET redeemed_at = ?,
                redeemed_by_student_id = ?,
                redeemed_for_mock_id = ?
            WHERE code_hash = ?
              AND is_active = 1
              AND redeemed_at IS NULL
              AND EXISTS (
                SELECT 1 FROM students WHERE id = ?
              )
              AND EXISTS (
                SELECT 1 FROM mocks
                WHERE id = ? AND status = 'published'
              )
          `).bind(
            now,
            studentId,
            mockId,
            codeHash,
            studentId,
            mockId
          ),

          // Create examination attempt after successful redemption.
          env.DB.prepare(`
            INSERT INTO attempts (
              id,
              student_id,
              mock_id,
              started_at,
              status
            )
            SELECT ?, ?, ?, ?, 'in_progress'
            WHERE EXISTS (
              SELECT 1 FROM access_codes
              WHERE code_hash = ?
                AND redeemed_by_student_id = ?
            )
          `).bind(
            attemptId,
            studentId,
            mockId,
            now,
            codeHash,
            studentId
          )
        ]);

        const changes = results?.[1]?.meta?.changes || 0;

        if (changes !== 1) {
          return json({
            error: "That access code is invalid, inactive or has already been used."
          }, 400);
        }

        return json({
          ok: true,
          attemptId,
          message: "Access code accepted. Your examination attempt has been created."
        });
      }

      // Serve the existing A² Tutorials website.
      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response("Website assets are not configured.", {
        status: 500
      });

    } catch (error) {
      console.error("A² Tutorials Worker error:", error);

      return json({
        error: "A temporary server error occurred. Please try again."
      }, 500);
    }
  }
};
        
