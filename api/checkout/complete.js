module.exports=async(req,res)=>{
res.setHeader('Cache-Control','no-store');
if(req.method!=='POST'){res.setHeader('Allow','POST');return res.status(405).json({error:'Method not allowed'});}
const id=req.body?.id;
if(typeof id!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id))return res.status(400).json({error:'Invalid session ID'});
try{
const r=await fetch(process.env.SUPABASE_URL+'/rest/v1/rpc/complete_demo_checkout',{method:'POST',headers:{apikey:process.env.SUPABASE_SECRET_KEY,'Content-Type':'application/json'},body:JSON.stringify({p_id:id})});
if(!r.ok)throw Error();
if(await r.json()!==true)return res.status(409).json({error:'Session expired, missing or already completed'});
return res.status(200).json({id,status:'simulated',mode:'simulation',payment_processed:false});
}catch{return res.status(500).json({error:'Simulation unavailable'});}
};