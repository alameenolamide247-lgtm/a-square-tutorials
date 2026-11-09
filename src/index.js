
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
              a.total_questions,
ROUND((julianday(COALESCE(a.submitted_at, CURRENT_TIMESTAMP)) - julianday(a.started_at)) * 86400) AS time_spent_seconds
            FROM attempts a
            JOIN students s ON s.id = a.student_id
            JOIN mocks m ON m.id = a.mock_id
            ORDER BY COALESCE(a.submitted_at, a.started_at) DESC
            LIMIT 500
          `).all();

                    return json({ results: result.results || [] });
        }

        // Generate access codes
        if (url.pathname === "/api/admin/codes" && method === "POST") {
          let body;

          try {
            body = await request.json();
          } catch {
            return json({ error: "Invalid request." }, 400);
          }

          const count = Number(body.count);

          if (!Number.isInteger(count) || count < 1 || count > 100) {
            return json({ error: "Generate between 1 and 100 codes." }, 400);
          }

          const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
          const generated = [];
          const statements = [];

          for (let i = 0; i < count; i++) {
            const bytes = crypto.getRandomValues(new Uint8Array(12));
            let randomPart = "";

            for (const byte of bytes) {
              randomPart += alphabet[byte % alphabet.length];
            }

            const code = "ASQ-" + randomPart;
            generated.push(code);

            statements.push(
              env.DB.prepare(`
                INSERT INTO access_codes (code_hash, is_active)
                VALUES (?, 1)
              `).bind(await sha256(code))
            );
          }

          await env.DB.batch(statements);

          return json({ ok: true, codes: generated }, 201);
        }

        // List access codes
        if (url.pathname === "/api/admin/codes" && method === "GET") {
          const result = await env.DB.prepare(`
            SELECT
              ac.id,
              ac.is_active,
              ac.created_at,
              ac.redeemed_at,
              s.full_name,
              m.title AS mock_title
            FROM access_codes ac
            LEFT JOIN students s
              ON s.id = ac.redeemed_by_student_id
            LEFT JOIN mocks m
              ON m.id = ac.redeemed_for_mock_id
            ORDER BY ac.created_at DESC
            LIMIT 500
          `).all();

          return json({ codes: result.results || [] });
        }

        // Activate or deactivate an unused code
        const codeMatch = url.pathname.match(
          /^\/api\/admin\/codes\/(\d+)$/
        );

        if (codeMatch && method === "PATCH") {
          let body;

          try {
            body = await request.json();
          } catch {
            return json({ error: "Invalid request." }, 400);
          }

          const isActive = Number(body.is_active);

          if (![0, 1].includes(isActive)) {
            return json({ error: "Invalid code status." }, 400);
          }

          const result = await env.DB.prepare(`
            UPDATE access_codes
            SET is_active = ?
            WHERE id = ?
              AND redeemed_at IS NULL
          `).bind(isActive, Number(codeMatch[1])).run();

          if (!result.meta?.changes) {
            return json({
              error: "Code not found or already redeemed."
            }, 400);
          }

          return json({ ok: true });
        }
      }
      // ==========================================
      // STUDENT CBT EXAMINATION API

// Load questions for an active examination
const examQuestionsMatch = url.pathname.match(
  /^\/api\/exam\/([^/]+)\/questions$/
);

if (examQuestionsMatch && method === "GET") {
  const attemptId = examQuestionsMatch[1];

  const attempt = await env.DB.prepare(`
    SELECT a.id, a.mock_id, a.started_at, a.status,
           m.title, m.duration_minutes
    FROM attempts a
    JOIN mocks m ON m.id = a.mock_id
    WHERE a.id = ?
  `).bind(attemptId).first();

  if (!attempt) {
    return json({ error: "Examination not found." }, 404);
  }

  if (attempt.status !== "in_progress") {
    return json({ error: "This examination has already ended." }, 400);
  }

  const questions = await env.DB.prepare(`
    SELECT id, question_text, options_json, sort_order
    FROM questions
    WHERE mock_id = ?
    ORDER BY sort_order ASC
  `).bind(attempt.mock_id).all();

  const startedAt = new Date(attempt.started_at).getTime();
  const deadline = startedAt + attempt.duration_minutes * 60000;
  const remainingSeconds = Math.max(
    0,
    Math.floor((deadline - Date.now()) / 1000)
  );

  return json({
    attemptId: attempt.id,
    title: attempt.title,
    durationMinutes: attempt.duration_minutes,
    remainingSeconds,
    questions: (questions.results || []).map(q => ({
      id: q.id,
      questionText: q.question_text,
      options: JSON.parse(q.options_json)
    }))
  });
}

// Submit and automatically mark an examination
const examSubmitMatch = url.pathname.match(
  /^\/api\/exam\/([^/]+)\/submit$/
);

if (examSubmitMatch && method === "POST") {
  const attemptId = examSubmitMatch[1];

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid submission." }, 400);
  }

  const answers = body.answers || {};

  if (
    !answers ||
    typeof answers !== "object" ||
    Array.isArray(answers)
  ) {
    return json({ error: "Invalid answers." }, 400);
  }

  const attempt = await env.DB.prepare(`
    SELECT a.id, a.mock_id, a.started_at, a.status,
           m.duration_minutes
    FROM attempts a
    JOIN mocks m ON m.id = a.mock_id
    WHERE a.id = ?
  `).bind(attemptId).first();

  if (!attempt) {
    return json({ error: "Examination not found." }, 404);
  }

  if (attempt.status !== "in_progress") {
    return json({ error: "This examination has already been submitted." }, 400);
  }

  const questionsResult = await env.DB.prepare(`
    SELECT id, correct_option, explanation
    FROM questions
    WHERE mock_id = ?
    ORDER BY sort_order ASC
  `).bind(attempt.mock_id).all();

  const questions = questionsResult.results || [];
  const validIds = new Set(questions.map(q => q.id));

  for (const questionId of Object.keys(answers)) {
    if (!validIds.has(questionId)) {
      return json({ error: "Invalid question in submission." }, 400);
    }

    const selected = String(answers[questionId] || "").toUpperCase();

    if (!["A", "B", "C", "D"].includes(selected)) {
      return json({ error: "Invalid answer option." }, 400);
    }
  }

  let score = 0;

  const statements = [];

  for (const q of questions) {
    const selected = String(answers[q.id] || "").toUpperCase();
    const correct = String(q.correct_option).toUpperCase();

    if (selected && selected === correct) {
      score++;
    }

    if (selected) {
      statements.push(
        env.DB.prepare(`
          INSERT INTO answers
          (attempt_id, question_id, selected_option, answered_at)
          VALUES (?, ?, ?, ?)
        `).bind(
          attemptId,
          q.id,
          selected,
          new Date().toISOString()
        )
      );
    }
  }

  const now = new Date();
  const deadline =
    new Date(attempt.started_at).getTime() +
    attempt.duration_minutes * 60000;

  const finalStatus =
    now.getTime() >= deadline ? "expired" : "submitted";

  statements.push(
    env.DB.prepare(`
      UPDATE attempts
      SET submitted_at = ?,
          status = ?,
          score = ?,
          total_questions = ?
      WHERE id = ? AND status = 'in_progress'
    `).bind(
      now.toISOString(),
      finalStatus,
      score,
      questions.length,
      attemptId
    )
  );

  const results = await env.DB.batch(statements);

  const updateResult = results[results.length - 1];

  if (!updateResult?.meta?.changes) {
    return json({
      error: "This examination has already been submitted."
    }, 409);
  }

  return json({
    ok: true,
    score,
    totalQuestions: questions.length,
    status: finalStatus,
    message: "Your examination has been marked successfully."
  });
}
      // Review examination answers after submission
const examReviewMatch = url.pathname.match(
  /^\/api\/exam\/([^/]+)\/review$/
);

if (examReviewMatch && method === "GET") {
  const attemptId = examReviewMatch[1];

  const attempt = await env.DB.prepare(`
    SELECT id, status
    FROM attempts
    WHERE id = ?
  `).bind(attemptId).first();

  if (!attempt) {
    return json({ error: "Examination not found." }, 404);
  }

  if (!["submitted", "expired"].includes(attempt.status)) {
    return json({
      error: "You can only review an examination after submission."
    }, 403);
  }

  const result = await env.DB.prepare(`
    SELECT
      q.id,
      q.question_text,
      q.options_json,
      q.correct_option,
      q.explanation,
      a.selected_option
    FROM questions q
    LEFT JOIN answers a
      ON a.question_id = q.id
      AND a.attempt_id = ?
    WHERE q.mock_id = (
      SELECT mock_id FROM attempts WHERE id = ?
    )
    ORDER BY q.sort_order ASC
  `).bind(attemptId, attemptId).all();

  const reviews = (result.results || []).map(q => ({
    questionId: q.id,
    questionText: q.question_text,
    options: JSON.parse(q.options_json),
    selectedOption: q.selected_option,
    correctOption: q.correct_option,
    explanation: q.explanation,
    isCorrect: q.selected_option === q.correct_option
  }));

  return json({
    ok: true,
    reviews
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
        
