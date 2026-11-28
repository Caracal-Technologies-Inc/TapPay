module.exports = async function(req,res) {
  res.setHeader('Cache-Control','no-store');
  const base=process.env.SUPABASE_URL, key=process.env.SUPABASE_SECRET_KEY;
  const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const headers={apikey:key,'Content-Type':'application/json'};
  const db=async(path,options={})=>{
    const r=await fetch(base+'/rest/v1/'+path,{...options,headers:{...headers,...options.headers}});
    if(!r.ok) throw new Error('Database request failed');
    return r.json();
  };
  try {
    if(req.method==='POST'){
      const auth=req.headers.authorization;
      if(!auth || !auth.startsWith('Bearer ')) return res.status(401).json({error:'Sign in required'});
      const u=await fetch(base+'/auth/v1/user',{headers:{apikey:key,Authorization:auth}});
      if(!u.ok) return res.status(401).json({error:'Invalid session'});
      const user=await u.json();
      if(!user.email_confirmed_at) return res.status(403).json({error:'Confirm email'});
      const {merchant_id,amount_minor,currency}=req.body||{};
      if(typeof merchant_id!=='string'||!uuid.test(merchant_id)||!Number.isSafeInteger(amount_minor)||amount_minor<1||amount_minor>1000000||currency!=='CAD') return res.status(400).json({error:'Invalid checkout'});
      const merchants=await db('merchants?select=id&id=eq.'+merchant_id+'&owner_id=eq.'+user.id);
      if(!merchants.length) return res.status(403).json({error:'Merchant not authorized'});
      const rows=await db('checkout_sessions',{method:'POST',headers:{Prefer:'return=representation'},body:JSON.stringify({merchant_id,amount_minor,currency,status:'created'})});
      const s=rows[0];
      return res.status(201).json({id:s.id,amount_minor:s.amount_minor,currency:s.currency,status:s.status,mode:'simulation',expires_at:new Date(Date.parse(s.created_at)+900000).toISOString()});
    }
    if(req.method==='GET'){
      const id=req.query.id;
      if(typeof id!=='string'||!uuid.test(id)) return res.status(400).json({error:'Invalid session ID'});
      const rows=await db('checkout_sessions?select=id,amount_minor,currency,status,created_at,merchants(name)&id=eq.'+id);
      if(!rows.length) return res.status(404).json({error:'Session not found'});
      const s=rows[0], expiry=Date.parse(s.created_at)+900000;
      return res.status(200).json({id:s.id,merchant:s.merchants?.name,amount_minor:s.amount_minor,currency:s.currency,status:s.status==='created'&&Date.now()>=expiry?'expired':s.status,expires_at:new Date(expiry).toISOString(),mode:'simulation'});
    }
    res.setHeader('Allow','GET, POST');
    return res.status(405).json({error:'Method not allowed'});
  } catch { return res.status(500).json({error:'Checkout unavailable'}); }
};
