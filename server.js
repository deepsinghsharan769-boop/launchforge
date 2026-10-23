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

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
app.set('trust proxy', 1);
const db=new Database(path.join(__dirname,'launchforge.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL, description TEXT DEFAULT '', html TEXT NOT NULL, css TEXT DEFAULT '', js TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deployed_url TEXT DEFAULT '', deploy_status TEXT DEFAULT 'Not deployed', deploy_logs TEXT DEFAULT '');
`);
const adminUser=process.env.ADMIN_USERNAME || 'admin';
const adminPass=process.env.ADMIN_PASSWORD;
if(!adminPass){console.warn('ADMIN_PASSWORD is not set. Login is disabled until configured. Copy .env.example to .env.');}
else {
 const existing=db.prepare('SELECT id FROM users WHERE username=?').get(adminUser);
 if(!existing) db.prepare('INSERT INTO users(username,password_hash) VALUES(?,?)').run(adminUser,bcrypt.hashSync(adminPass,12));
}
const SQLiteStore=SQLiteStoreFactory(session);
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'2mb'}));
app.use(session({store:new SQLiteStore({db:'sessions.sqlite',dir:__dirname}),secret:process.env.SESSION_SECRET||'development-only-change-me',
 resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.COOKIE_SECURE==='true',maxAge:8*60*60*1000}}));
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:2*1024*1024}});
const requireAuth=(req,res,next)=>req.session.user?next():res.status(401).json({error:'Please sign in again.'});
const now=()=>new Date().toISOString();
app.post('/api/login',async(req,res)=>{
 const {username,password}=req.body||{};
 if(typeof username!=='string'||typeof password!=='string'||username.length>200||password.length>300)return res.status(400).json({error:'Enter your username and password.'});
 const user=db.prepare('SELECT * FROM users WHERE username=?').get(username);
 if(!user||!await bcrypt.compare(password,user.password_hash))return res.status(401).json({error:'Incorrect username or password.'});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Could not create session.'});req.session.user={id:user.id,username:user.username};res.json({user:{username:user.username}});});
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',(req,res)=>req.session.user?res.json({user:req.session.user}):res.status(401).json({error:'Not signed in'}));
app.get('/api/projects',requireAuth,(req,res)=>res.json(db.prepare('SELECT id,name,description,created_at,updated_at,deployed_url,deploy_status FROM projects WHERE user_id=? ORDER BY updated_at DESC').all(req.session.user.id)));
app.post('/api/projects',requireAuth,(req,res)=>{
 const name=String(req.body?.name||'Untitled project').slice(0,100), id=crypto.randomUUID(), t=now();
 const starter=starterFromPrompt(String(req.body?.prompt||'A clean modern landing page'));
 db.prepare('INSERT INTO projects(id,user_id,name,description,html,css,js,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)')
 .run(id,req.session.user.id,name,String(req.body?.prompt||'').slice(0,1000),starter.html,starter.css,starter.js,t,t);
 res.status(201).json(getProject(id,req.session.user.id));
});
function getProject(id,uid){return db.prepare('SELECT * FROM projects WHERE id=? AND user_id=?').get(id,uid);}
app.get('/api/projects/:id',requireAuth,(req,res)=>{const p=getProject(req.params.id,req.session.user.id);p?res.json(p):res.status(404).json({error:'Project not found'});});
app.put('/api/projects/:id',requireAuth,(req,res)=>{
 const p=getProject(req.params.id,req.session.user.id);if(!p)return res.status(404).json({error:'Project not found'});
 const b=req.body||{}, name=String(b.name??p.name).slice(0,100), html=String(b.html??p.html), css=String(b.css??p.css), js=String(b.js??p.js);
 if(html.length>800000||css.length>800000||js.length>800000)return res.status(413).json({error:'Project files are too large.'});
 db.prepare('UPDATE projects SET name=?,description=?,html=?,css=?,js=?,updated_at=? WHERE id=? AND user_id=?')
 .run(name,String(b.description??p.description).slice(0,1000),html,css,js,now(),p.id,req.session.user.id);
 res.json(getProject(p.id,req.session.user.id));
});
app.post('/api/projects/:id/duplicate',requireAuth,(req,res)=>{
 const p=getProject(req.params.id,req.session.user.id);if(!p)return res.status(404).json({error:'Project not found'});
 const id=crypto.randomUUID(),t=now();db.prepare('INSERT INTO projects(id,user_id,name,description,html,css,js,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)')
 .run(id,p.user_id,`${p.name} copy`.slice(0,100),p.description,p.html,p.css,p.js,t,t);res.status(201).json(getProject(id,p.user_id));
});
app.delete('/api/projects/:id',requireAuth,(req,res)=>{const r=db.prepare('DELETE FROM projects WHERE id=? AND user_id=?').run(req.params.id,req.session.user.id);r.changes?res.json({ok:true}):res.status(404).json({error:'Project not found'});});
app.get('/api/projects/:id/export',requireAuth,(req,res)=>{const p=getProject(req.params.id,req.session.user.id);if(!p)return res.status(404).json({error:'Project not found'});res.setHeader('Content-Disposition',`attachment; filename="${p.name.replace(/[^a-z0-9_-]/gi,'-')}.json"`);res.json({format:'launchforge-project-v1',name:p.name,description:p.description,html:p.html,css:p.css,js:p.js});});
app.post('/api/import',requireAuth,upload.single('file'),(req,res)=>{
 try {if(!req.file)return res.status(400).json({error:'Choose a project JSON file.'});const x=JSON.parse(req.file.buffer.toString('utf8'));if(!x||typeof x.html!=='string')return res.status(400).json({error:'Invalid project file.'});
 const id=crypto.randomUUID(),t=now();db.prepare('INSERT INTO projects(id,user_id,name,description,html,css,js,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)')
 .run(id,req.session.user.id,String(x.name||'Imported project').slice(0,100),String(x.description||'').slice(0,1000),x.html,String(x.css||''),String(x.js||''),t,t);res.status(201).json(getProject(id,req.session.user.id));
 }catch{return res.status(400).json({error:'Could not read that project file.'});}
});
app.post('/api/ai/generate',requireAuth,async(req,res)=>{
 const prompt=String(req.body?.prompt||'').trim();if(!prompt)return res.status(400).json({error:'Describe the app you want to create.'});
 if(process.env.AI_API_KEY){
  try{
   const r=await fetch((process.env.AI_BASE_URL||'https://api.openai.com/v1')+'/chat/completions',{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${process.env.AI_API_KEY}`},body:JSON.stringify({model:process.env.AI_MODEL||'gpt-4o-mini',temperature:0.4,messages:[{role:'system',content:'Return only JSON with keys name, html, css, js. Generate a complete single-page web app. No markdown fences. Do not include external scripts. Keep HTML body contents only; CSS and JS separate.'},{role:'user',content:prompt}]})});
   if(!r.ok)throw new Error(`AI provider returned ${r.status}`);const data=await r.json();const out=JSON.parse(data.choices?.[0]?.message?.content||'{}');
   if(typeof out.html!=='string')throw new Error('AI response format was invalid');return res.json({name:String(out.name||'AI generated app'),html:out.html,css:String(out.css||''),js:String(out.js||'')});
  }catch(e){return res.status(502).json({error:'AI generation failed. Check your server-side AI settings and try again.',detail:process.env.NODE_ENV==='production'?undefined:e.message});}
 }
 res.json({name:prompt.slice(0,60)||'AI starter app',...starterFromPrompt(prompt),note:'Generated with the built-in prompt starter. Add AI_API_KEY on the server for model-powered generation.'});
});
app.post('/api/projects/:id/deploy',requireAuth,async(req,res)=>{
 const p=getProject(req.params.id,req.session.user.id);if(!p)return res.status(404).json({error:'Project not found'});
 const provider=req.body?.provider;
 try{
  let url='',logs='';
  if(provider==='vercel'){
   if(!process.env.VERCEL_TOKEN)return res.status(400).json({error:'Set VERCEL_TOKEN in the server environment first.'});
   const html=renderHtml(p),payload={name:p.name.toLowerCase().replace(/[^a-z0-9-]/g,'-').replace(/^-+|-+$/g,'').slice(0,50)||'launchforge-app',files:[{file:'index.html',data:html}],projectSettings:{framework:null}};
   const r=await fetch('https://api.vercel.com/v13/deployments',{method:'POST',headers:{Authorization:`Bearer ${process.env.VERCEL_TOKEN}`,'Content-Type':'application/json'},body:JSON.stringify(payload)});
   const data=await r.json();if(!r.ok)throw new Error(data.error?.message||`Vercel API ${r.status}`);url=data.url?`https://${data.url}`:'';logs=JSON.stringify(data,null,2);
  }else if(provider==='netlify'){
   if(!process.env.NETLIFY_TOKEN)return res.status(400).json({error:'Set NETLIFY_TOKEN in the server environment first.'});
   const r=await fetch('https://api.netlify.com/api/v1/sites',{method:'POST',headers:{Authorization:`Bearer ${process.env.NETLIFY_TOKEN}`,'Content-Type':'application/json'},body:JSON.stringify({name:p.name.toLowerCase().replace(/[^a-z0-9-]/g,'-').slice(0,50)+'-'+p.id.slice(0,6)})});
   const site=await r.json();if(!r.ok)throw new Error(site.message||`Netlify API ${r.status}`);
   const zip=await makeZipBuffer({'index.html':renderHtml(p)});const d=await fetch(`https://api.netlify.com/api/v1/sites/${site.id}/deploys`,{method:'POST',headers:{Authorization:`Bearer ${process.env.NETLIFY_TOKEN}`,'Content-Type':'application/zip'},body:zip});
   const deploy=await d.json();if(!d.ok)throw new Error(deploy.message||`Netlify deploy API ${d.status}`);url=site.ssl_url||site.url||'';logs=JSON.stringify({site,deploy},null,2);
  }else return res.status(400).json({error:'Choose Vercel or Netlify.'});
  db.prepare('UPDATE projects SET deployed_url=?,deploy_status=?,deploy_logs=?,updated_at=? WHERE id=?').run(url,'Deployment requested',logs,now(),p.id);
  res.json({url,status:'Deployment requested',logs});
 }catch(e){db.prepare('UPDATE projects SET deploy_status=?,deploy_logs=?,updated_at=? WHERE id=?').run('Failed',String(e.message),now(),p.id);res.status(502).json({error:'Deployment failed',detail:e.message});}
});
app.get('/api/projects/:id/deploy-logs',requireAuth,(req,res)=>{const p=getProject(req.params.id,req.session.user.id);p?res.json({status:p.deploy_status,url:p.deployed_url,logs:p.deploy_logs}):res.status(404).json({error:'Project not found'});});
function starterFromPrompt(prompt){
 const safe=prompt.replace(/[<>&"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]));
 return {html:`<main class="hero"><nav><strong>Studio<span>+</span></strong><a href="#features">Features</a><a href="#about">About</a><button class="nav-cta" onclick="document.querySelector('#about').scrollIntoView({behavior:'smooth'})">Get started ↗</button></nav><section class="intro"><div class="eyebrow">✦ MADE FOR WHAT'S NEXT</div><h1>${safe.slice(0,90)}</h1><p>A polished, responsive starting point. Customize the content, colors, and interactions in the editor.</p><div class="actions"><button onclick="document.querySelector('#features').scrollIntoView({behavior:'smooth'})">Explore the experience ↗</button><a href="#about">Learn more</a></div><div class="orb"></div></section><section id="features" class="features"><article><span>01 / DESIGN</span><h2>Clarity in every detail</h2><p>Thoughtful layouts that put your content first.</p></article><article><span>02 / BUILD</span><h2>Made to move fast</h2><p>A flexible foundation for your next big idea.</p></article><article><span>03 / LAUNCH</span><h2>Ready for the world</h2><p>Responsive, accessible, and easy to evolve.</p></article></section><section id="about" class="about"><p>YOUR NEXT CHAPTER STARTS HERE</p><h2>Good ideas deserve a great home.</h2></section><footer>© ${new Date().getFullYear()} Studio+. Built with LaunchForge.</footer></main>`,css:`@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');*{box-sizing:border-box}body{margin:0;background:#0b0d12;color:#f7f7fb;font-family:'DM Sans',sans-serif}.hero{max-width:1180px;margin:auto;padding:28px 6%}nav{display:flex;align-items:center;gap:28px;color:#b9bdca;font-size:13px}nav strong{font:700 23px 'Space Grotesk';color:#fff;margin-right:auto}nav strong span{color:#a78bfa}nav a,.actions a{color:inherit;text-decoration:none}.nav-cta,button{cursor:pointer;border:0;border-radius:999px;padding:12px 18px;background:#a78bfa;color:#11111a;font-weight:700}.intro{position:relative;overflow:hidden;padding:100px 0 110px;max-width:760px}.eyebrow,.features article span,.about>p{color:#a78bfa;font-size:11px;letter-spacing:2px;font-weight:700}.intro h1{font:600 clamp(42px,7vw,78px)/1.04 'Space Grotesk';letter-spacing:-3px;margin:22px 0;max-width:800px}.intro p{color:#a9adba;line-height:1.8;max-width:520px}.actions{display:flex;align-items:center;gap:24px;margin-top:28px;font-size:13px}.orb{position:absolute;z-index:-1;right:-220px;top:10px;width:420px;height:420px;border-radius:50%;background:radial-gradient(circle at 35% 35%,#8b5cf6,#27205b 45%,transparent 70%);filter:blur(20px);opacity:.6}.features{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.features article{padding:26px;border:1px solid #252733;background:#11131b;border-radius:18px}.features h2{font:600 21px 'Space Grotesk'}.features p{color:#a9adba;line-height:1.7;font-size:14px}.about{margin:90px 0;padding:44px;border-radius:24px;background:linear-gradient(120deg,#1c1831,#121520);border:1px solid #302747}.about h2{font:600 clamp(28px,4vw,44px) 'Space Grotesk';max-width:600px}footer{padding:25px 0;color:#777d8d;font-size:12px}@media(max-width:650px){nav{gap:12px}nav>a{display:none}.intro{padding:72px 0}.features{grid-template-columns:1fr}.about{padding:28px}.intro h1{letter-spacing:-1.5px}}`,js:`document.querySelectorAll('button').forEach(button=>button.addEventListener('click',()=>{button.animate([{transform:'scale(1)'},{transform:'scale(.97)'},{transform:'scale(1)'}],{duration:180})}));`};
}
function renderHtml(p){return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${p.name.replace(/[<>&"]/g,'')}</title><style>${p.css}</style></head><body>${p.html}<script>${p.js.replace(/<\/script/gi,'<\\/script')}</script></body></html>`;}
async function makeZipBuffer(files){const {default:JSZip}=await import('jszip').catch(()=>({default:null}));if(!JSZip)throw new Error('Netlify ZIP adapter dependency missing; run npm install jszip');const z=new JSZip();for(const [n,c] of Object.entries(files))z.file(n,c);return z.generateAsync({type:'nodebuffer'});}
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Unexpected server error.'});});
const port=Number(process.env.PORT||3000);app.listen(port,()=>console.log(`LaunchForge running at http://localhost:${port}`));
