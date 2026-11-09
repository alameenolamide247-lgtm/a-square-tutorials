
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
            // ADMIN DASHBOARD API
      if (url.pathname.startsWith("/api/admin/") &&
          !["/api/admin/login", "/api/admin/session", "/api/admin/logout"].includes(url.pathname)) {

        const authenticated = await verifyAdminSession(request, env.ADMIN_PASSWORD);

        if (!authenticated) {
          return json({ error: "Session expired. Please sign in again." }, 401);
        }

        if (!env.DB) {
          return json({ error: "Database is not configured." }, 500);
        }

        // Dashboard statistics
        if (url.pathname === "/api/admin/overview" && method === "GET") {
          const [mocks, students, attempts, codes] = await Promise.all([
            env.DB.prepare("SELECT COUNT(*) AS count FROM mocks").first(),
            env.DB.prepare("SELECT COUNT(*) AS count FROM students").first(),
            env.DB.prepare("SELECT COUNT(*) AS count FROM attempts").first(),
            env.DB.prepare("SELECT COUNT(*) AS count FROM access_codes WHERE is_active = 1 AND redeemed_at IS NULL").first()
          ]);

          return json({
            mocks: mocks?.count || 0,
            students: students?.count || 0,
            attempts: attempts?.count || 0,
            unusedCodes: codes?.count || 0
          });
        }

        // List all mocks
        if (url.pathname === "/api/admin/mocks" && method === "GET") {
          const result = await env.DB.prepare(`
            SELECT m.*,
              (SELECT COUNT(*) FROM questions q WHERE q.mock_id = m.id) AS saved_questions
            FROM mocks m
            ORDER BY m.created_at DESC
          `).all();

          return json({
            mocks: (result.results || []).map(m => ({
              ...m,
              subjects: JSON.parse(m.subjects_json || "[]")
            }))
          });
        }

        // Create a mock and save its questions
        if (url.pathname === "/api/admin/mocks" && method === "POST") {
          let body;

          try {
            body = await request.json();
          } catch {
            return json({ error: "Invalid request." }, 400);
          }

          const title = String(body.title || "").trim();
          const subjects = Array.isArray(body.subjects)
            ? [...new Set(body.subjects)]
            : [];
          const duration = Number(body.durationMinutes);
          const questions = Array.isArray(body.questions)
            ? body.questions
            : [];
          const status = body.status === "published" ? "published" : "draft";

          const validSubjects = [
            "Use of English",
            "Mathematics",
            "Physics",
            "Chemistry",
            "Biology"
          ];

          if (title.length < 3 || title.length > 120) {
            return json({ error: "Enter a mock title between 3 and 120 characters." }, 400);
          }

          if (!subjects.length || subjects.some(s => !validSubjects.includes(s))) {
            return json({ error: "Select at least one valid subject." }, 400);
          }

          if (!Number.isInteger(duration) || duration < 1 || duration > 600) {
            return json({ error: "Duration must be between 1 and 600 minutes." }, 400);
          }

          if (!questions.length || questions.length > 300) {
            return json({ error: "Add between 1 and 300 questions." }, 400);
          }

          for (const q of questions) {
            const options = q.options || {};
            const keys = ["A", "B", "C", "D"];

            if (
              !String(q.questionText || "").trim() ||
              keys.some(k => !String(options[k] || "").trim()) ||
              !keys.includes(String(q.correctOption || "").toUpperCase())
            ) {
              return json({
                error: "Every question needs question text, four options and a correct answer."
              }, 400);
            }
          }

          const mockId = crypto.randomUUID();

          const statements = [
            env.DB.prepare(`
              INSERT INTO mocks
              (id, title, subjects_json, duration_minutes, question_count, status)
              VALUES (?, ?, ?, ?, ?, ?)
            `).bind(
              mockId,
              title,
              JSON.stringify(subjects),
              duration,
              questions.length,
              status
            )
          ];

          questions.forEach((q, index) => {
            statements.push(
              env.DB.prepare(`
                INSERT INTO questions
                (id, mock_id, question_text, options_json, correct_option, explanation, sort_order)
                VALUES (?, ?, ?, ?, ?, ?, ?)
              `).bind(
                crypto.randomUUID(),
                mockId,
                String(q.questionText).trim(),
                JSON.stringify(q.options),
                String(q.correctOption).toUpperCase(),
                String(q.explanation || "").trim() || null,
                index + 1
              )
            );
          });

          await env.DB.batch(statements);

          return json({
            ok: true,
            mockId,
            message: status === "published"
              ? "Mock created and published."
              : "Mock saved as draft."
          }, 201);
        }

        // Change mock status
        const statusMatch = url.pathname.match(
          /^\/api\/admin\/mocks\/([^/]+)\/status$/
        );

        if (statusMatch && method === "PATCH") {
          let body;

          try {
            body = await request.json();
          } catch {
            return json({ error: "Invalid request." }, 400);
          }

          const status = String(body.status || "");

          if (!["draft", "published", "archived"].includes(status)) {
            return json({ error: "Invalid status." }, 400);
          }

          const result = await env.DB.prepare(
            "UPDATE mocks SET status = ? WHERE id = ?"
          ).bind(status, statusMatch[1]).run();

          if (!result.meta?.changes) {
            return json({ error: "Mock not found." }, 404);
          }

          return json({ ok: true });
        }

        // List students
        if (url.pathname === "/api/admin/students" && method === "GET") {
          const result = await env.DB.prepare(`
            SELECT s.id, s.full_name, s.created_at,
              COUNT(DISTINCT a.id) AS attempts_count
            FROM students s
            LEFT JOIN attempts a ON a.student_id = s.id
            GROUP BY s.id
            ORDER BY s.created_at DESC
            LIMIT 500
          `).all();

          return json({ students: result.results || [] });
        }

        // List examination results
        if (url.pathname === "/api/admin/results" && method === "GET") {
          const result = await env.DB.prepare(`
            SELECT
              a.id,
              s.full_name,
              m.title AS mock_title,
              a.started_at,
              a.submitted_at,
              a.status,
              a.score,
              a.total_questions
            FROM attempts a
            JOIN students s ON s.id = a.student_id
            JOIN mocks m ON m.id = a.mock_id
            ORDER BY COALESCE(a.submitted_at, a.started_at) DESC
            LIMIT 500
          `).all();

          return json({ results: result.results || [] });
        }
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
        
