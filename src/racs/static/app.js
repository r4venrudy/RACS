'use strict';
const $ = id => document.getElementById(id);
let token = '', challenge = null, active = null, timer = null;
function note(message, error=false){$('notice').textContent=message;$('notice').className=error?'error':'';}
async function api(path, options={}){
 if(!token) throw new Error('Unlock the workspace with your local API token first.');
 const response=await fetch('/api/'+path,{...options,headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json',...(options.headers||{})}});
 if(!response.ok){const data=await response.json();throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail));}
 return response;
}
const post=(path,body)=>api(path,{method:'POST',body:JSON.stringify(body)});
function handle(fn){return async event=>{event?.preventDefault();try{await fn(event);}catch(error){note(error.message,true);}};}
$('login').addEventListener('submit',handle(async()=>{token=$('api-token').value.trim();await api('scans');$('api-token').value='';$('unlock').hidden=true;$('connection').textContent='Unlocked';note('Local workspace unlocked. Start by proving ownership.');await history();}));
$('challenge-form').addEventListener('submit',handle(async()=>{challenge=await(await post('challenges',{target:$('target').value,method:$('method').value})).json();$('proof-location').textContent=challenge.location;$('proof-token').textContent=challenge.token;$('challenge').hidden=false;note('Challenge created. Publish the proof before checking ownership.');}));
$('verify').addEventListener('click',handle(async()=>{if(!challenge)throw new Error('Create a challenge first.');const grant=await(await post('challenges/'+challenge.id+'/verify',{})).json();$('verification').textContent='Verified until '+new Date(grant.expires_at*1000).toLocaleString();$('challenge').hidden=true;$('proof-token').textContent='';challenge=null;note('Ownership confirmed. Declare the exact read-only paths you want to test.');}));
$('revoke').addEventListener('click',handle(async()=>{await post('targets/revoke',{target:$('target').value});note('Ownership revoked; active sessions for this origin were cancelled.');$('verification').textContent='Verification required.';}));
$('recover').addEventListener('click',handle(async()=>{await post('targets/recover',{target:$('target').value});note('Target recovery acknowledged. You can start a new verified scan.');}));
$('scan-form').addEventListener('submit',handle(async()=>{
 const probes=$('probes').value.trim().split('\n').filter(Boolean).map(line=>{const [path,parameter,baseline,sql_context='string']=line.split(',');if(!path||!parameter||!baseline)throw new Error('Each endpoint line needs path, parameter and baseline.');return {path:path.trim(),parameter:parameter.trim(),baseline:baseline.trim(),sql_context:sql_context.trim()};});
 const credentials={};if($('owner-token').value)credentials[$('owner-alias').value]=$('owner-token').value;if($('other-token').value)credentials[$('other-alias').value]=$('other-token').value;
 const plan={checks:[...document.querySelectorAll('input[name=check]:checked')].map(e=>e.value),header_path:$('header-path').value,probes,access_cases:JSON.parse($('access-cases').value||'[]'),read_only_confirmed:$('consent').checked};
 const job=await(await post('scans',{target:$('target').value,plan,credentials})).json();$('owner-token').value='';$('other-token').value='';active=job.id;note('Scan queued. Every request remains ownership-gated and bounded.');await loadReport();
}));
function element(tag,text,cls){const e=document.createElement(tag);if(text!=null)e.textContent=text;if(cls)e.className=cls;return e;}
async function loadReport(){
 if(!active)return;const report=await(await api('scans/'+active+'/report')).json();
 const s=report.session;$('scan-status').textContent=s.origin+' · '+s.status+' · '+s.detail;
 const running=['queued','running'].includes(s.status);$('cancel').disabled=!running;$('download-html').disabled=running;$('download-pdf').disabled=running;
 $('coverage').replaceChildren();const seen=new Set();
 for(const o of report.outcomes){seen.add(o.check);const row=element('div',null,'coverage');row.append(element('b',o.check),element('span',o.status,'badge'),element('span',o.detail));$('coverage').append(row);}
 for(const name of ['headers','xss','sqli','idor'])if(!seen.has(name)){const row=element('div',null,'coverage');row.append(element('b',name),element('span',running?'pending':'not performed','badge'),element('span',running?'Waiting for this check.':'Not selected or interrupted.'));$('coverage').append(row);}
 $('findings').replaceChildren();for(const f of report.findings){const card=element('article',null,'finding');card.append(element('h3',f.type),element('div',f.severity+' severity / '+f.confidence+' confidence / '+f.verification_status,'badge'),element('p',f.affected_url+' · parameter: '+(f.affected_parameter||'none'),'location'));for(const [label,key] of [['Confidence','confidence_rationale'],['Evidence','evidence'],['Remediation','remediation']])card.append(element('h3',label),element('p',f[key]));card.append(element('h3','Reproduction'));const list=element('ol');for(const step of f.reproduction_steps)list.append(element('li',step));card.append(list,element('h3','Sample fix'),element('pre',f.sample_fix_snippet));$('findings').append(card);}
 if(!running&&!report.findings.length)$('findings').append(element('p','No verified findings recorded. Check the coverage above; skipped checks are not passes.'));
 clearTimeout(timer);if(running)timer=setTimeout(()=>handle(loadReport)(),1000);else await history();
}
async function history(){const sessions=await(await api('scans')).json();$('history').replaceChildren();for(const s of sessions){const row=element('div',null,'session');const text=element('div',s.origin);text.append(element('small',new Date(s.created_at*1000).toLocaleString()+' · '+s.status));const button=element('button','View report','secondary');button.addEventListener('click',handle(async()=>{active=s.id;await loadReport();}));row.append(text,button);$('history').append(row);}}
$('refresh').addEventListener('click',handle(history));$('cancel').addEventListener('click',handle(async()=>{await post('scans/'+active+'/cancel',{});await loadReport();}));
for(const format of ['html','pdf'])$('download-'+format).addEventListener('click',handle(async()=>{const response=await api('scans/'+active+'/report.'+format);const blob=await response.blob(),url=URL.createObjectURL(blob),a=element('a');a.href=url;a.download='racs-'+active+'.'+format;a.click();setTimeout(()=>URL.revokeObjectURL(url),5000);}));
