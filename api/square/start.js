const crypto=require('node:crypto');
module.exports=async(req,res)=>{
res.setHeader('Cache-Control','no-store');
if(req.method!=='POST')return res.status(405).end();
const {SUPABASE_URL:u,SUPABASE_SECRET_KEY:k,SQUARE_APPLICATION_ID:id,SQUARE_APPLICATION_SECRET:s,SQUARE_REDIRECT_URI:redirect}=process.env;
if(!u||!k||!id||!s||!redirect)return res.status(503).end();
const auth=req.headers.authorization;
if(!auth||!auth.startsWith('Bearer '))return res.status(401).end();
try{
const r=await fetch(u+'/auth/v1/user',{headers:{apikey:k,Authorization:auth}});
if(!r.ok)return res.status(401).end();
const user=await r.json();
if(!user.id||!user.email_confirmed_at)return res.status(403).end();
const nonce=crypto.randomBytes(32).toString('hex');
const saved=await fetch(u+'/rest/v1/square_oauth_states',{method:'POST',headers:{apikey:k,'Content-Type':'application/json'},body:JSON.stringify({nonce,owner_id:user.id,expires_at:new Date(Date.now()+600000).toISOString()})});
if(!saved.ok)return res.status(503).end();
const payload=Buffer.from(JSON.stringify({uid:user.id,nonce,exp:Date.now()+600000})).toString('base64url');
const state=payload+'.'+crypto.createHmac('sha256',s).update(payload).digest('hex');
res.setHeader('Set-Cookie','square_bound_state='+state+'; Path=/api/square; HttpOnly; Secure; SameSite=Lax; Max-Age=600');
const url=new URL('https://connect.squareup.com/oauth2/authorize');
url.search=new URLSearchParams({client_id:id,scope:'MERCHANT_PROFILE_READ PAYMENTS_READ PAYMENTS_WRITE PAYMENTS_WRITE_IN_PERSON',state,redirect_uri:redirect,session:'false'}).toString();
return res.status(200).json({url:url.toString()});
}catch{return res.status(502).end();}
};