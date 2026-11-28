const crypto = require('node:crypto');
module.exports = (req,res) => {
 res.setHeader('Cache-Control','no-store');
 if(req.method!=='GET') return res.status(405).end();
 const {SQUARE_APPLICATION_ID:id,SQUARE_APPLICATION_SECRET:secret,SQUARE_REDIRECT_URI:redirect}=process.env;
 if(!id||!secret||!redirect) return res.status(503).send('Square configuration incomplete');
 const nonce=crypto.randomBytes(32).toString('hex');
 const state=nonce+'.'+crypto.createHmac('sha256',secret).update(nonce).digest('hex');
 res.setHeader('Set-Cookie','square_oauth_state='+state+'; Path=/api/square; HttpOnly; Secure; SameSite=Lax; Max-Age=600');
 const url=new URL('https://connect.squareup.com/oauth2/authorize');
 url.search=new URLSearchParams({client_id:id,scope:'MERCHANT_PROFILE_READ PAYMENTS_READ PAYMENTS_WRITE',state,redirect_uri:redirect,session:'false'}).toString();
 return res.redirect(302,url.toString());
};