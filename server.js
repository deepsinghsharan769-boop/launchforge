import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import Database from 'better-sqlite3';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

const db = new Database(path.join(__dirname, 'launchforge.sqlite'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  );
`);

const adminUser = process.env.ADMIN_USERNAME || 'admin';
const adminPass = process.env.ADMIN_PASSWORD;

if (!adminPass) {
  console.warn('ADMIN_PASSWORD is not set. Configure it in Render environment variables.');
} else {
  const existing = db.prepare('SELECT id FROM users WHERE username=?').get(adminUser);
  if (!existing) {
    db.prepare('INSERT INTO users(username,password_hash) VALUES(?,?)')
      .run(adminUser, bcrypt.hashSync(adminPass, 12));
  }
}

const SQLiteStore = SQLiteStoreFactory(session);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'development-only-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }
});

const requireAuth = (req, res, next) =>
  req.session.user
    ? next()
    : res.status(401).json({ error: 'Please sign in again.' });

const now = () => new Date().toISOString();

const supabaseUrl = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

async function supabaseRequest(table, {
  method = 'GET',
  query = '',
  body,
  prefer
} = {}) {
  if (!supabaseUrl || !supabaseKey) {
    const error = new Error(
      'Supabase is not configured. Add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in Render.'
    );
    error.status = 503;
    throw error;
  }

  const headers = {
    apikey: supabaseKey,
    Authorization: `Bearer ${supabaseKey}`,
    'Content-Type': 'application/json'
  };

  if (prefer) headers.Prefer = prefer;

  const response = await fetch(
    `${supabaseUrl}/rest/v1/${table}${query ? `?${query}` : ''}`,
    {
      method,
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {})
    }
  );

  const raw = await response.text();
  let data = null;

  try {
    data = raw ? JSON.parse(raw) : null;
  } catch {
    data = raw;
  }

  if (!response.ok) {
    console.error(
      'Supabase request failed:',
      response.status,
      typeof data === 'string' ? data : JSON.stringify(data)
    );

    const error = new Error(
      'Supabase could not save or load this project. Check the table columns and Render environment variables.'
    );

    error.status = response.status >= 500 ? 502 : 400;
    throw error;
  }

  return data;
}

function userFilter(uid) {
  return `user_id=eq.${encodeURIComponent(String(uid))}`;
}

async function listProjects(uid) {
  return await supabaseRequest('projects', {
    query: `${userFilter(uid)}&select=id,name,description,created_at,updated_at,deployed_url,deploy_status&order=updated_at.desc`
  });
}

async function getProject(id, uid) {
  const rows = await supabaseRequest('projects', {
    query: `id=eq.${encodeURIComponent(id)}&${userFilter(uid)}&select=*`
  });

  return rows?.[0] || null;
}

async function insertProject(project) {
  const rows = await supabaseRequest('projects', {
    method: 'POST',
    query: 'select=*',
    prefer: 'return=representation',
    body: project
  });

  return rows?.[0] || null;
}

async function updateProject(id, uid, patch) {
  const rows = await supabaseRequest('projects', {
    method: 'PATCH',
    query: `id=eq.${encodeURIComponent(id)}&${userFilter(uid)}&select=*`,
    prefer: 'return=representation',
    body: patch
  });

  return rows?.[0] || null;
}

async function deleteProject(id, uid) {
  const rows = await supabaseRequest('projects', {
    method: 'DELETE',
    query: `id=eq.${encodeURIComponent(id)}&${userFilter(uid)}&select=id`,
    prefer: 'return=representation'
  });

  return Array.isArray(rows) && rows.length > 0;
}

function handleError(res, error) {
  console.error(error);

  return res.status(error.status || 500).json({
    error: error.status
      ? error.message
      : 'Unexpected server error. Please try again.'
  });
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (
    typeof username !== 'string' ||
    typeof password !== 'string' ||
    username.length > 200 ||
    password.length > 300
  ) {
    return res.status(400).json({
      error: 'Enter your username and password.'
    });
  }

  const user = db.prepare(
    'SELECT * FROM users WHERE username=?'
  ).get(username);

  if (!user || !await bcrypt.compare(password, user.password_hash)) {
    return res.status(401).json({
      error: 'Incorrect username or password.'
    });
  }

  req.session.regenerate(err => {
    if (err) {
      return res.status(500).json({
        error: 'Could not create session.'
      });
    }

    req.session.user = {
      id: user.id,
      username: user.username
    };

    res.json({ user: { username: user.username } });
  });
});

app.post('/api/logout', (req, res) =>
  req.session.destroy(() => res.json({ ok: true }))
);

app.get('/api/me', (req, res) =>
  req.session.user
    ? res.json({ user: req.session.user })
    : res.status(401).json({ error: 'Not signed in' })
);

app.get('/api/projects', requireAuth, async (req, res) => {
  try {
    res.json(await listProjects(req.session.user.id));
  } catch (error) {
    handleError(res, error);
  }
});

app.post('/api/projects', requireAuth, async (req, res) => {
  try {
    const prompt = String(
      req.body?.prompt || 'A clean modern landing page'
    ).slice(0, 1000);

    const starter = starterFromPrompt(prompt);

    const project = await insertProject({
      id: crypto.randomUUID(),
      user_id: req.session.user.id,
      name: String(
        req.body?.name || prompt || 'Untitled project'
      ).slice(0, 100),
      description: prompt,
      html: starter.html,
      css: starter.css,
      js: starter.js,
      created_at: now(),
      updated_at: now(),
      deployed_url: '',
      deploy_status: 'Not deployed',
      deploy_logs: ''
    });

    if (!project) {
      return res.status(500).json({
        error: 'Project was not saved.'
      });
    }

    res.status(201).json(project);
  } catch (error) {
    handleError(res, error);
  }
});
app.get('/api/projects/:id', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.session.user.id);
    project
      ? res.json(project)
      : res.status(404).json({ error: 'Project not found' });
  } catch (error) {
    handleError(res, error);
  }
});

app.put('/api/projects/:id', requireAuth, async (req, res) => {
  try {
    const current = await getProject(req.params.id, req.session.user.id);
    if (!current) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const b = req.body || {};
    const html = String(b.html ?? current.html ?? '');
    const css = String(b.css ?? current.css ?? '');
    const js = String(b.js ?? current.js ?? '');

    if (html.length > 800000 || css.length > 800000 || js.length > 800000) {
      return res.status(413).json({ error: 'Project files are too large.' });
    }

    const saved = await updateProject(current.id, req.session.user.id, {
      name: String(b.name ?? current.name).slice(0, 100),
      description: String(b.description ?? current.description ?? '').slice(0, 1000),
      html,
      css,
      js,
      updated_at: now()
    });

    saved
      ? res.json(saved)
      : res.status(404).json({ error: 'Project not found' });
  } catch (error) {
    handleError(res, error);
  }
});

app.post('/api/projects/:id/duplicate', requireAuth, async (req, res) => {
  try {
    const p = await getProject(req.params.id, req.session.user.id);
    if (!p) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const t = now();
    const copy = await insertProject({
      id: crypto.randomUUID(),
      user_id: req.session.user.id,
      name: `${p.name} copy`.slice(0, 100),
      description: p.description || '',
      html: p.html || '',
      css: p.css || '',
      js: p.js || '',
      created_at: t,
      updated_at: t,
      deployed_url: '',
      deploy_status: 'Not deployed',
      deploy_logs: ''
    });

    res.status(201).json(copy);
  } catch (error) {
    handleError(res, error);
  }
});

app.delete('/api/projects/:id', requireAuth, async (req, res) => {
  try {
    const deleted = await deleteProject(req.params.id, req.session.user.id);
    deleted
      ? res.json({ ok: true })
      : res.status(404).json({ error: 'Project not found' });
  } catch (error) {
    handleError(res, error);
  }
});

app.get('/api/projects/:id/export', requireAuth, async (req, res) => {
  try {
    const p = await getProject(req.params.id, req.session.user.id);
    if (!p) {
      return res.status(404).json({ error: 'Project not found' });
    }

    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${p.name.replace(/[^a-z0-9_-]/gi, '-')}.json"`
    );

    res.json({
      format: 'launchforge-project-v1',
      name: p.name,
      description: p.description,
      html: p.html,
      css: p.css,
      js: p.js
    });
  } catch (error) {
    handleError(res, error);
  }
});

app.post('/api/import', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Choose a project JSON file.' });
    }

    const x = JSON.parse(req.file.buffer.toString('utf8'));
    if (!x || typeof x.html !== 'string') {
      return res.status(400).json({ error: 'Invalid project file.' });
    }

    const t = now();
    const project = await insertProject({
      id: crypto.randomUUID(),
      user_id: req.session.user.id,
      name: String(x.name || 'Imported project').slice(0, 100),
      description: String(x.description || '').slice(0, 1000),
      html: x.html,
      css: String(x.css || ''),
      js: String(x.js || ''),
      created_at: t,
      updated_at: t,
      deployed_url: '',
      deploy_status: 'Not deployed',
      deploy_logs: ''
    });

    res.status(201).json(project);
  } catch (error) {
    if (error instanceof SyntaxError) {
      return res.status(400).json({ error: 'Could not read that project file.' });
    }
    handleError(res, error);
  }
});
app.post('/api/ai/generate', requireAuth, async (req, res) => {
  const prompt = String(req.body?.prompt || '').trim();

  if (!prompt) {
    return res.status(400).json({
      error: 'Describe the app you want to create.'
    });
  }

  if (process.env.AI_API_KEY) {
    try {
      const response = await fetch(
        (process.env.AI_BASE_URL || 'https://api.openai.com/v1') +
          '/chat/completions',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${process.env.AI_API_KEY}`
          },
          body: JSON.stringify({
            model: process.env.AI_MODEL || 'gpt-4o-mini',
            temperature: 0.4,
            messages: [
              {
                role: 'system',
                content:
                  'Return only JSON with keys name, html, css, js. Generate a complete single-page web app. No markdown fences. Keep HTML body contents only; CSS and JS separate.'
              },
              { role: 'user', content: prompt }
            ]
          })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(`AI provider returned ${response.status}`);
      }

      const out = JSON.parse(
        data.choices?.[0]?.message?.content || '{}'
      );

      if (typeof out.html !== 'string') {
        throw new Error('AI response format was invalid');
      }

      return res.json({
        name: String(out.name || 'AI generated app'),
        html: out.html,
        css: String(out.css || ''),
        js: String(out.js || '')
      });
    } catch (error) {
      return res.status(502).json({
        error: 'AI generation failed. Check your server-side AI settings and try again.',
        ...(process.env.NODE_ENV !== 'production'
          ? { detail: error.message }
          : {})
      });
    }
  }

  res.json({
    name: prompt.slice(0, 60) || 'AI starter app',
    ...starterFromPrompt(prompt),
    note: 'Generated with the built-in prompt starter. Add AI_API_KEY on the server for model-powered generation.'
  });
});

app.post('/api/projects/:id/deploy', requireAuth, async (req, res) => {
  try {
    const p = await getProject(req.params.id, req.session.user.id);

    if (!p) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const provider = req.body?.provider;
    let url = '';
    let logs = '';

    if (provider === 'vercel') {
      if (!process.env.VERCEL_TOKEN) {
        return res.status(400).json({
          error: 'Set VERCEL_TOKEN in the server environment first.'
        });
      }

      const payload = {
        name: p.name.toLowerCase()
          .replace(/[^a-z0-9-]/g, '-')
          .replace(/^-+|-+$/g, '')
          .slice(0, 50) || 'launchforge-app',
        files: [{ file: 'index.html', data: renderHtml(p) }],
        projectSettings: { framework: null }
      };

      const response = await fetch(
        'https://api.vercel.com/v13/deployments',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${process.env.VERCEL_TOKEN}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error?.message || `Vercel API ${response.status}`
        );
      }

      url = data.url ? `https://${data.url}` : '';
      logs = JSON.stringify(data, null, 2);
    } else if (provider === 'netlify') {
      if (!process.env.NETLIFY_TOKEN) {
        return res.status(400).json({
          error: 'Set NETLIFY_TOKEN in the server environment first.'
        });
      }

      const siteResponse = await fetch(
        'https://api.netlify.com/api/v1/sites',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${process.env.NETLIFY_TOKEN}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            name: p.name.toLowerCase()
              .replace(/[^a-z0-9-]/g, '-')
              .slice(0, 40) + '-' + p.id.slice(0, 6)
          })
        }
      );

      const site = await siteResponse.json();

      if (!siteResponse.ok) {
        throw new Error(
          site.message || `Netlify API ${siteResponse.status}`
        );
      }

      const zip = await makeZipBuffer({
        'index.html': renderHtml(p)
      });

      const deployResponse = await fetch(
        `https://api.netlify.com/api/v1/sites/${site.id}/deploys`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${process.env.NETLIFY_TOKEN}`,
            'Content-Type': 'application/zip'
          },
          body: zip
        }
      );

      const deployment = await deployResponse.json();

      if (!deployResponse.ok) {
        throw new Error(
          deployment.message ||
          `Netlify API ${deployResponse.status}`
        );
      }

      url = site.ssl_url || site.url || '';
      logs = JSON.stringify({ site, deployment }, null, 2);
    } else {
      return res.status(400).json({
        error: 'Choose Vercel or Netlify.'
      });
    }

    await updateProject(p.id, req.session.user.id, {
      deployed_url: url,
      deploy_status: 'Deployment requested',
      deploy_logs: logs,
      updated_at: now()
    });

    res.json({
      url,
      status: 'Deployment requested',
      logs
    });
  } catch (error) {
    try {
      await updateProject(req.params.id, req.session.user.id, {
        deploy_status: 'Failed',
        deploy_logs: String(error.message),
        updated_at: now()
      });
    } catch {}

    res.status(502).json({
      error: 'Deployment failed',
      detail: error.message
    });
  }
});

app.get('/api/projects/:id/deploy-logs', requireAuth, async (req, res) => {
  try {
    const p = await getProject(req.params.id, req.session.user.id);

    if (!p) {
      return res.status(404).json({ error: 'Project not found' });
    }

    res.json({
      status: p.deploy_status,
      url: p.deployed_url,
      logs: p.deploy_logs
    });
  } catch (error) {
    handleError(res, error);
  }
});

function starterFromPrompt(prompt) {
  const safe = String(prompt).replace(/[<>&"]/g, c => ({
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    '"': '&quot;'
  }[c]));

  return {
    html: `<main class="hero">
      <nav>
        <strong>LaunchForge<span>+</span></strong>
        <a href="#features">Features</a>
        <a href="#about">About</a>
        <button class="nav-cta" onclick="document.querySelector('#about').scrollIntoView({behavior:'smooth'})">Get started ↗</button>
      </nav>
      <section class="intro">
        <div class="eyebrow">✦ MADE FOR WHAT'S NEXT</div>
        <h1>${safe.slice(0, 90)}</h1>
        <p>A polished, responsive starting point. Customize the content, colors, and interactions in the editor.</p>
        <div class="actions">
          <button onclick="document.querySelector('#features').scrollIntoView({behavior:'smooth'})">Explore the experience ↗</button>
          <a href="#about">Learn more</a>
        </div>
        <div class="orb"></div>
      </section>
      <section id="features" class="features">
        <article><span>01 / DESIGN</span><h2>Clarity in every detail</h2><p>Thoughtful layouts that put your content first.</p></article>
        <article><span>02 / BUILD</span><h2>Made to move fast</h2><p>A flexible foundation for your next big idea.</p></article>
        <article><span>03 / LAUNCH</span><h2>Ready for the world</h2><p>Responsive, accessible, and easy to evolve.</p></article>
      </section>
      <section id="about" class="about">
        <p>YOUR NEXT CHAPTER STARTS HERE</p>
        <h2>Good ideas deserve a great home.</h2>
      </section>
      <footer>© ${new Date().getFullYear()} LaunchForge. Built for your next idea.</footer>
    </main>`,
    css: `*{box-sizing:border-box}
body{margin:0;background:#0b0d12;color:#f7f7fb;font-family:Arial,sans-serif}
.hero{max-width:1180px;margin:auto;padding:28px 6%}
nav{display:flex;align-items:center;gap:24px;color:#b9bdca;font-size:13px;flex-wrap:wrap}
nav strong{font-size:23px;color:#fff;margin-right:auto}
nav strong span{color:#a78bfa}
nav a,.actions a{color:inherit;text-decoration:none}
button{cursor:pointer;border:0;border-radius:999px;padding:12px 18px;background:#a78bfa;color:#11111a;font-weight:700}
.intro{position:relative;padding:90px 0;max-width:760px}
.eyebrow,.features article span,.about>p{color:#a78bfa;font-size:11px;letter-spacing:2px;font-weight:700}
.intro h1{font-size:clamp(42px,7vw,78px);line-height:1.05;margin:22px 0}
.intro p{color:#a9adba;line-height:1.8;max-width:520px}
.actions{display:flex;align-items:center;gap:24px;margin-top:28px}
.features{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
.features article{padding:26px;border:1px solid #252733;background:#11131b;border-radius:18px}
.features h2{font-size:21px}
.features p{color:#a9adba;line-height:1.7;font-size:14px}
.about{margin:70px 0;padding:36px;border-radius:24px;background:#171525;border:1px solid #302747}
footer{padding:25px 0;color:#777d8d;font-size:12px}
@media(max-width:650px){.features{grid-template-columns:1fr}.intro{padding:60px 0}.about{padding:24px}}\`,
    js: `document.querySelectorAll('button').forEach(button=>button.addEventListener('click',()=>{button.animate([{transform:'scale(1)'},{transform:'scale(.97)'},{transform:'scale(1)'}],{duration:180})}));\`
  };
}

function renderHtml(p) {
  const title = String(p.name || 'LaunchForge App')
    .replace(/[<>&"]/g, '');

  return \`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>\${title}</title>
<style>\${p.css || ''}</style>
</head>
<body>
\${p.html || ''}
<script>\${String(p.js || '').replace(/<\\/script/gi, '<\\\\/script')}</script>
</body>
</html>\`;
}

async function makeZipBuffer(files) {
  const { default: JSZip } = await import('jszip')
    .catch(() => ({ default: null }));

  if (!JSZip) {
    throw new Error(
      'Netlify ZIP dependency missing. Install jszip in package.json.'
    );
  }

  const zip = new JSZip();

  for (const [name, content] of Object.entries(files)) {
    zip.file(name, content);
  }

  return zip.generateAsync({ type: 'nodebuffer' });
}

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: 'Unexpected server error.' });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () =>
  console.log(`LaunchForge running on port ${port}`)
);
