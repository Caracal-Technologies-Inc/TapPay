const crypto=require('node:crypto');
module.exports=(req,res)=>{
 res.setHeader('Cache-Control','no-store');
 res.setHeader('Referrer-Policy','no-referrer');
 if(req.method!=='GET')return res.status(405).end();
 const state=req.query.state;
 const cookie=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('square_oauth_state='))?.slice(19);
 res.setHeader('Set-Cookie','square_oauth_state=; Path=/api/square; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
 if(typeof state!=='string'||!cookie||state!==cookie||!process.env.SQUARE_APPLICATION_SECRET)return res.status(400).send('Invalid or expired authorization session.');
 const [nonce,sig]=state.split('.');
 if(!/^[a-f0-9]{64}$/.test(nonce||'')||!/^[a-f0-9]{64}$/.test(sig||''))return res.status(400).end();
 const expected=crypto.createHmac('sha256',process.env.SQUARE_APPLICATION_SECRET).update(nonce).digest('hex');
 if(!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected)))return res.status(400).end();
 if(req.query.error||typeof req.query.code!=='string')return res.status(400).send('Square authorization was not completed.');
 return res.status(200).send('Square authorization callback verified. Token exchange is disabled until authenticated merchant binding and secure token storage are configured. No merchant connection or payment has been created.');
};