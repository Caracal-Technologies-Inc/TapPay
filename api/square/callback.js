const crypto=require('node:crypto');
module.exports=async(req,res)=>{
res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','no-referrer');
if(req.method!=='GET')return res.status(405).end();
const {SUPABASE_URL:u,SUPABASE_SECRET_KEY:k,SQUARE_APPLICATION_ID:id,SQUARE_APPLICATION_SECRET:s,SQUARE_REDIRECT_URI:redirect,TOKEN_ENCRYPTION_KEY:ek}=process.env;
if(!u||!k||!id||!s||!redirect||!ek||!/^[a-f0-9]{64}$/i.test(ek))return res.status(503).send('Server configuration incomplete');
const state=req.query.state,cookie=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('square_bound_state='))?.slice(19);
res.setHeader('Set-Cookie','square_bound_state=; Path=/api/square; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
try{
if(typeof state!=='string'||state!==cookie||typeof req.query.code!=='string')return res.status(400).send('Invalid authorization');
const [p,sig]=state.split('.');if(!/^[a-f0-9]{64}$/.test(sig||'')||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(crypto.createHmac('sha256',s).update(p).digest('hex'))))return res.status(400).end();
const a=JSON.parse(Buffer.from(p,'base64url').toString());if(a.exp<Date.now()||!a.uid||!a.nonce)return res.status(400).end();
const h={apikey:k,'Content-Type':'application/json',Prefer:'return=representation'};
const db=async(path,method='GET',body)=>{const r=await fetch(u+'/rest/v1/'+path,{method,headers:h,body:body===undefined?undefined:JSON.stringify(body)});if(!r.ok)throw Error('database');return r.json();};
const consumed=await db('square_oauth_states?nonce=eq.'+encodeURIComponent(a.nonce)+'&owner_id=eq.'+encodeURIComponent(a.uid)+'&expires_at=gt.'+encodeURIComponent(new Date().toISOString()),'DELETE');if(consumed.length!==1)return res.status(400).send('Expired or reused authorization');
const r=await fetch('https://connect.squareup.com/oauth2/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:id,client_secret:s,code:req.query.code,grant_type:'authorization_code',redirect_uri:redirect})});
const t=await r.json();if(!r.ok||!t.access_token||!t.merchant_id)return res.status(502).send('Square token exchange failed');
const existing=await db('square_merchant_credentials?square_merchant_id=eq.'+encodeURIComponent(t.merchant_id)+'&select=merchant_id,merchants(owner_id)');
if(existing.length&&existing[0].merchants?.owner_id!==a.uid)return res.status(409).send('Merchant already connected to another account');
const merchant=existing.length?existing[0].merchant_id:(await db('merchants','POST',{owner_id:a.uid,name:'Square merchant'}))[0].id;
const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',Buffer.from(ek,'hex'),iv);cipher.setAAD(Buffer.from(merchant));
const encrypted=Buffer.concat([cipher.update(JSON.stringify(t),'utf8'),cipher.final()]);
const data={merchant_id:merchant,square_merchant_id:t.merchant_id,encrypted_credentials:[iv,cipher.getAuthTag(),encrypted].map(x=>x.toString('base64')).join('.'),expires_at:t.expires_at||null,updated_at:new Date().toISOString()};
if(existing.length)await db('square_merchant_credentials?merchant_id=eq.'+encodeURIComponent(merchant),'PATCH',data);else await db('square_merchant_credentials','POST',data);
return res.status(200).send('Square merchant connected. No payment has been processed.');
}catch{return res.status(502).send('Merchant connection failed. Restart authorization.');}
};