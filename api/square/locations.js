const crypto=require('node:crypto');
module.exports=async(req,res)=>{
res.setHeader('Cache-Control','no-store');
if(req.method!=='GET')return res.status(405).end();
const {SUPABASE_URL:u,SUPABASE_SECRET_KEY:k,TOKEN_ENCRYPTION_KEY:ek}=process.env;
if(!u||!k||!ek)return res.status(503).end();
const auth=req.headers.authorization;if(!auth?.startsWith('Bearer '))return res.status(401).end();
try{
const a=await fetch(u+'/auth/v1/user',{headers:{apikey:k,Authorization:auth}});if(!a.ok)return res.status(401).end();
const user=await a.json();
const r=await fetch(u+'/rest/v1/square_merchant_credentials?select=merchant_id,encrypted_credentials,expires_at,merchants!inner(owner_id)&merchants.owner_id=eq.'+encodeURIComponent(user.id),{headers:{apikey:k}});
if(!r.ok)return res.status(502).end();
const rows=await r.json();if(!rows.length)return res.status(404).json({error:'No connected merchant'});
const out=[];
for(const row of rows){if(Date.parse(row.expires_at)<=Date.now())continue;const [iv,tag,encrypted]=row.encrypted_credentials.split('.').map(x=>Buffer.from(x,'base64'));const d=crypto.createDecipheriv('aes-256-gcm',Buffer.from(ek,'hex'),iv);d.setAAD(Buffer.from(row.merchant_id));d.setAuthTag(tag);const t=JSON.parse(Buffer.concat([d.update(encrypted),d.final()]).toString());const q=await fetch('https://connect.squareup.com/v2/locations',{headers:{Authorization:'Bearer '+t.access_token}});if(!q.ok)return res.status(502).json({error:'Square locations request failed'});const j=await q.json();out.push({merchant_id:row.merchant_id,locations:(j.locations||[]).map(x=>({id:x.id,name:x.name,status:x.status,currency:x.currency}))});}
return res.status(200).json({merchants:out});
}catch{return res.status(502).json({error:'Merchant verification failed'});}
};