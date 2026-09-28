import express from 'express';
import dotenv from 'dotenv';
import { InferenceClient } from '@huggingface/inference';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Webhook must read the untouched request bytes for HMAC verification.
app.post('/api/payment/webhook',express.raw({type:'application/json'}),(req,res)=>{
  try{
    if(!process.env.RAZORPAY_WEBHOOK_SECRET)return res.status(503).send('Webhook secret not configured');
    const sig=req.headers['x-razorpay-signature'];const expected=crypto.createHmac('sha256',process.env.RAZORPAY_WEBHOOK_SECRET).update(req.body).digest('hex');if(sig!==expected)return res.status(400).send('Invalid signature');
    const event=JSON.parse(req.body.toString()); if(event.event==='payment.captured'){const p=event.payload?.payment?.entity;const email=p?.notes?.email;const plan=PLANS[String(p?.notes?.plan||'').toUpperCase()];if(email&&plan){const db=readDb();const u=db.users.find(x=>x.email===email);if(u){u.plan=plan.name;u.credits={images:plan.images,videos:plan.videos};}const o=db.orders.find(x=>x.id===p.order_id);if(o){o.status='paid';o.paymentId=p.id;o.paidAt=new Date().toISOString()}writeDb(db)}}res.json({ok:true});
  }catch(e){res.status(500).send('Webhook error')}
});

app.use(express.json({limit:'15mb'}));
app.use(express.urlencoded({extended:true, limit:'2mb'}));
app.use(express.static('.'));

const hf = process.env.HF_TOKEN ? new InferenceClient(process.env.HF_TOKEN) : null;
const LIMITS = { images: 2, videos: 2 };
const MODELS = {
  image: 'black-forest-labs/FLUX.1-dev',
  video: 'Lightricks/LTX-Video-0.9.8-13B-distilled',
  imageToVideo: 'Wan-AI/Wan2.1-I2V-14B-720P'
};
const PLANS = {
  PRO: { name:'PRO', amount:19900, price:199, images:50, videos:20, ads:false },
  CREATOR: { name:'CREATOR', amount:49900, price:499, images:150, videos:60, ads:false }
};
const dataDir = path.join(__dirname,'data');
const dbFile = path.join(dataDir,'db.json');
if(!fs.existsSync(dataDir)) fs.mkdirSync(dataDir,{recursive:true});
if(!fs.existsSync(dbFile)) fs.writeFileSync(dbFile, JSON.stringify({users:[],orders:[],sessions:{},settings:{plans:PLANS}},null,2));
function readDb(){try{return JSON.parse(fs.readFileSync(dbFile,'utf8'))}catch{return {users:[],orders:[],sessions:{},settings:{plans:PLANS}}}}
function writeDb(db){fs.writeFileSync(dbFile,JSON.stringify(db,null,2))}

const usage = new Map();
function clientKey(req){return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'local'}
function today(){return new Date().toISOString().slice(0,10)}
function canUse(req,type){
  const k=clientKey(req), d=today(); let u=usage.get(k);
  if(!u || u.date!==d) u={date:d,images:0,videos:0};
  return u[type] < LIMITS[type];
}
function consume(req,type){
  const k=clientKey(req), d=today(); let u=usage.get(k);
  if(!u || u.date!==d) u={date:d,images:0,videos:0};
  u[type]++; usage.set(k,u);
}
function dims(ratio){if(ratio==='9:16')return{width:576,height:1024};if(ratio==='16:9')return{width:1024,height:576};return{width:768,height:768}}
function frames(v){return v==='5 sec'?121:v==='8 sec'?193:241}
function cleanError(e){return e?.message || e?.error || String(e)}
function hashPassword(p,salt=crypto.randomBytes(16).toString('hex')){return {salt,hash:crypto.scryptSync(p,salt,64).toString('hex')}}
function checkPassword(p,salt,hash){return crypto.timingSafeEqual(crypto.scryptSync(p,salt,64),Buffer.from(hash,'hex'))}
function newToken(){return crypto.randomBytes(32).toString('hex')}
function authUser(req){const token=req.headers.authorization?.replace(/^Bearer\s+/i,'') || req.cookies?.oneai_session; if(!token)return null; const db=readDb(); const email=db.sessions[token]; return email ? db.users.find(u=>u.email===email) || null : null}
function requireUser(req,res){const u=authUser(req); if(!u){res.status(401).json({error:'Login required.'});return null} return u}
function planFor(user){return user?.plan && PLANS[user.plan] ? PLANS[user.plan] : {name:'FREE',price:0,images:2,videos:2,ads:true}}
function razorReady(){return !!(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET)}

app.get('/api/health',(req,res)=>res.json({ok:true,provider:!!hf,free:LIMITS,models:MODELS,razorpay:razorReady(),admin:!!process.env.ADMIN_EMAIL&&!!process.env.ADMIN_PASSWORD}));
app.get('/api/config',(req,res)=>res.json({razorpayKeyId:process.env.RAZORPAY_KEY_ID||null,plans:Object.values(PLANS).map(p=>({name:p.name,price:p.price,images:p.images,videos:p.videos,ads:p.ads}))}));

app.post('/api/auth/register',(req,res)=>{
  const {email,password}=req.body||{}; if(!email||!password||password.length<6)return res.status(400).json({error:'Valid email and password (6+ characters) required.'});
  const e=String(email).trim().toLowerCase(); const db=readDb(); if(db.users.some(u=>u.email===e))return res.status(409).json({error:'Account already exists. Please login.'});
  const hp=hashPassword(password); db.users.push({email:e,...hp,plan:'FREE',credits:{images:0,videos:0},createdAt:new Date().toISOString()}); const token=newToken(); db.sessions[token]=e; writeDb(db); res.json({ok:true,token,user:{email:e,plan:'FREE'}});
});
app.post('/api/auth/login',(req,res)=>{
  const {email,password}=req.body||{}; const e=String(email||'').trim().toLowerCase(); const db=readDb(); const u=db.users.find(x=>x.email===e);
  if(!u||!checkPassword(String(password||''),u.salt,u.hash))return res.status(401).json({error:'Invalid email or password.'});
  const token=newToken(); db.sessions[token]=e; writeDb(db); res.json({ok:true,token,user:{email:e,plan:u.plan}});
});
app.get('/api/me',(req,res)=>{const u=authUser(req); if(!u)return res.json({user:null});res.json({user:{email:u.email,plan:u.plan,credits:u.credits||{images:0,videos:0}}})});
app.post('/api/logout',(req,res)=>{const token=req.headers.authorization?.replace(/^Bearer\s+/i,''); if(token){const db=readDb();delete db.sessions[token];writeDb(db)}res.json({ok:true})});

async function createImage(req,res){
  if(!hf)return res.status(500).json({error:'HF_TOKEN missing. Check your .env file.'});
  const user=authUser(req); const p=planFor(user); const type='images';
  if(user?.plan!=='FREE' && (user.credits?.images||0)>0){} else if(!canUse(req,type))return res.status(429).json({error:'Daily free image limit reached (2/day).'});
  const {prompt,style='Photorealistic cinematic',ratio='9:16',quality='High detail',width,height}=req.body||{}; if(!prompt)return res.status(400).json({error:'Prompt required.'});
  const d=dims(ratio); const full=`${prompt}. ${style}. Premium cinematic composition, expressive details, consistent subject, professional lighting, ${ratio} framing, ${quality} quality. No watermark, no random text, no duplicate subjects, no distorted anatomy.`;
  const image=await hf.textToImage({model:MODELS.image,provider:'fal-ai',inputs:full,width:width||d.width,height:height||d.height});
  const buf=Buffer.from(await image.arrayBuffer());
  if(user?.plan!=='FREE'){user.credits.images=Math.max(0,(user.credits?.images||0)-1);const db=readDb();const idx=db.users.findIndex(x=>x.email===user.email);db.users[idx]=user;writeDb(db)} else consume(req,type);
  res.set('Content-Type','image/png').set('Content-Disposition','attachment; filename="one-ai-image.png"').send(buf);
}
app.post('/api/image',async(req,res)=>{try{await createImage(req,res)}catch(e){res.status(500).json({error:cleanError(e)})}});

async function createVideo(req,res){
  if(!hf)return res.status(500).json({error:'HF_TOKEN missing. Check your .env file.'});
  const user=authUser(req); if(user?.plan==='FREE' && !canUse(req,'videos'))return res.status(429).json({error:'Daily free video limit reached (2/day).'});
  if(user?.plan!=='FREE' && (user.credits?.videos||0)<=0)return res.status(402).json({error:'No paid video credits left.'});
  const {prompt,duration='5 sec',ratio='9:16',camera='Cinematic tracking',voice='Natural Hindi',audio='Dialogue + SFX + ambience',numFrames}=req.body||{}; if(!prompt)return res.status(400).json({error:'Story/dialogue prompt required.'});
  const d=dims(ratio); const full=`${prompt}\nCamera: ${camera}. Format: ${ratio}. Target size: ${d.width}x${d.height}. Duration: ${duration}. Voice direction: ${voice}. Audio direction: ${audio}. Maintain character and scene continuity. Natural cinematic motion. Dialogue is production direction only; this visual model does not generate spoken audio or guarantee lip-sync.`;
  const video=await hf.textToVideo({model:MODELS.video,provider:'fal-ai',prompt:full,num_frames:numFrames||frames(duration),num_inference_steps:6});
  const buf=Buffer.from(await video.arrayBuffer());
  if(user?.plan!=='FREE'){user.credits.videos--;const db=readDb();const idx=db.users.findIndex(x=>x.email===user.email);db.users[idx]=user;writeDb(db)} else consume(req,'videos');
  res.set('Content-Type','video/mp4').set('Content-Disposition','attachment; filename="one-ai-video.mp4"').send(buf);
}
app.post('/api/video',async(req,res)=>{try{await createVideo(req,res)}catch(e){res.status(500).json({error:cleanError(e)})}});

app.post('/api/image-to-video',async(req,res)=>{
  try{
    if(!hf)return res.status(500).json({error:'HF_TOKEN missing. Check your .env file.'});
    const user=authUser(req); if(user?.plan==='FREE' && !canUse(req,'videos'))return res.status(429).json({error:'Daily free video limit reached (2/day).'}); if(user?.plan!=='FREE'&&(user.credits?.videos||0)<=0)return res.status(402).json({error:'No paid video credits left.'});
    const {image,prompt,duration='5 sec',ratio='9:16',camera='Cinematic tracking',numFrames}=req.body||{}; if(!image||!prompt)return res.status(400).json({error:'Image and motion prompt are required.'});
    const m=String(image).match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/);if(!m)return res.status(400).json({error:'Invalid image format. Use PNG, JPEG or WebP.'});
    const imageBuffer=Buffer.from(m[2],'base64');if(imageBuffer.length>10*1024*1024)return res.status(413).json({error:'Image too large. Use an image under 10 MB.'});
    const d=dims(ratio);const full=`${prompt}. ${camera}. Target format ${ratio}, target size ${d.width}x${d.height}, duration ${duration}. Smooth natural motion, consistent subject identity, stable background, cinematic movement. Do not change the main subject unexpectedly.`;
    const inputBlob=new Blob([imageBuffer],{type:m[1]});
    const video=await hf.imageToVideo({model:MODELS.imageToVideo,provider:'fal-ai',inputs:inputBlob,prompt:full,num_frames:numFrames||frames(duration),num_inference_steps:6});
    const buf=Buffer.from(await video.arrayBuffer());
    if(user?.plan!=='FREE'){user.credits.videos--;const db=readDb();const idx=db.users.findIndex(x=>x.email===user.email);db.users[idx]=user;writeDb(db)} else consume(req,'videos');
    res.set('Content-Type','video/mp4').set('Content-Disposition','attachment; filename="one-ai-image-to-video.mp4"').send(buf);
  }catch(e){res.status(500).json({error:cleanError(e)})}
});

// Razorpay: create order on server. Secret never goes to browser.
app.post('/api/payment/create-order',async(req,res)=>{
  try{
    const user=requireUser(req,res); if(!user)return;
    if(!razorReady())return res.status(503).json({error:'Razorpay is not connected yet. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET after account/KYC.'});
    const plan=PLANS[String(req.body?.plan||'').toUpperCase()]; if(!plan)return res.status(400).json({error:'Unknown plan.'});
    const auth=Buffer.from(`${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`).toString('base64');
    const r=await fetch('https://api.razorpay.com/v1/orders',{method:'POST',headers:{Authorization:`Basic ${auth}`,'Content-Type':'application/json'},body:JSON.stringify({amount:plan.amount,currency:'INR',receipt:`oneai_${Date.now()}`,notes:{email:user.email,plan:plan.name}})});
    const j=await r.json();if(!r.ok)return res.status(r.status).json({error:j?.error?.description||'Razorpay order creation failed'});
    const db=readDb();db.orders.push({id:j.id,email:user.email,plan:plan.name,amount:plan.amount,status:'created',createdAt:new Date().toISOString()});writeDb(db);res.json({ok:true,order:j,keyId:process.env.RAZORPAY_KEY_ID,plan:{name:plan.name,price:plan.price}});
  }catch(e){res.status(500).json({error:cleanError(e)})}
});
app.post('/api/payment/verify',async(req,res)=>{
  try{
    const user=requireUser(req,res);if(!user)return;
    const {razorpay_order_id,razorpay_payment_id,razorpay_signature,plan}=req.body||{};if(!razorpay_order_id||!razorpay_payment_id||!razorpay_signature)return res.status(400).json({error:'Payment verification data missing.'});
    const expected=crypto.createHmac('sha256',process.env.RAZORPAY_KEY_SECRET).update(`${razorpay_order_id}|${razorpay_payment_id}`).digest('hex');
    if(expected!==razorpay_signature)return res.status(400).json({error:'Payment signature verification failed.'});
    const p=PLANS[String(plan||'').toUpperCase()];if(!p)return res.status(400).json({error:'Unknown plan.'});
    const db=readDb();const u=db.users.find(x=>x.email===user.email);u.plan=p.name;u.credits={images:p.images,videos:p.videos};const o=db.orders.find(x=>x.id===razorpay_order_id);if(o){o.status='paid';o.paymentId=razorpay_payment_id;o.paidAt=new Date().toISOString()};writeDb(db);res.json({ok:true,user:{email:u.email,plan:u.plan,credits:u.credits}});
  }catch(e){res.status(500).json({error:cleanError(e)})}
});


function adminOk(req){const email=String(req.headers['x-admin-email']||'').trim().toLowerCase();const password=String(req.headers['x-admin-password']||'');return !!process.env.ADMIN_EMAIL && !!process.env.ADMIN_PASSWORD && email===String(process.env.ADMIN_EMAIL).trim().toLowerCase() && crypto.timingSafeEqual(Buffer.from(password),Buffer.from(process.env.ADMIN_PASSWORD))}
app.get('/api/admin/summary',(req,res)=>{if(!adminOk(req))return res.status(401).json({error:'Admin authentication required.'});const db=readDb();res.json({users:db.users.map(u=>({email:u.email,plan:u.plan,credits:u.credits,createdAt:u.createdAt})),orders:db.orders,plans:PLANS})});
app.post('/api/admin/plan',(req,res)=>{if(!adminOk(req))return res.status(401).json({error:'Admin authentication required.'});const {name,price,images,videos}=req.body||{};if(!PLANS[name])return res.status(400).json({error:'Only PRO or CREATOR can be edited in this prototype.'});PLANS[name].price=Number(price);PLANS[name].amount=Math.round(Number(price)*100);PLANS[name].images=Number(images);PLANS[name].videos=Number(videos);const db=readDb();db.settings.plans=PLANS;writeDb(db);res.json({ok:true,plans:PLANS})});

app.listen(process.env.PORT||3000,()=>console.log(`ONE AI V4 running on http://localhost:${process.env.PORT||3000}`));
