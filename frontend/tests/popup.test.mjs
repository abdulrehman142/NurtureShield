import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseHTML } from 'linkedom';
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const assessment=(overrides={})=>({url:'https://example.com',prediction:'legitimate',risk_level:'moderate',malicious_probability:.268,observed_characteristics:[],...overrides});
async function setup(query='') {
 const {document,window}=parseHTML(await readFile(new URL('../popup.html',import.meta.url),'utf8'));
 globalThis.document=document;globalThis.location=new URL('chrome-extension://'+'a'.repeat(32)+'/popup.html'+query);
 const opened=[];const sent=[];const state={reply:null};
 globalThis.chrome={runtime:{id:'a'.repeat(32),sendMessage:async message=>{sent.push(message);return state.reply;}},tabs:{query:async()=>[{url:'https://example.com',title:'Never read',favIconUrl:'https://forbidden.example/icon'}],create:async options=>opened.push(options)},storage:{onChanged:{addListener(){}}}};
 return {document,window,opened,sent,state,$:id=>document.getElementById(id),load:()=>import(`../popup.js?test=${Math.random()}`)};
}
test('compact default, current tab, loading, legitimate result, no indicators and another-link flow',async()=>{
 const {document,window,opened,sent,state,$,load}=await setup();await load();
 assert.equal($('url').tagName,'INPUT');assert.equal($('url').getAttribute('placeholder'),'Paste or enter a web address');
 assert.equal($('auth-state').hidden,true);assert.equal(document.getElementById('server'),null);assert.equal(document.getElementById('extension-id'),null);
 assert.equal($('result').hidden,true);
 const submit=()=>{$('checker').dispatchEvent(new window.Event('submit',{cancelable:true}));};
 submit();await tick();assert.equal($('error').hidden,false);assert.match($('error').textContent,/valid web address/);
 $('current-tab').dispatchEvent(new window.Event('click'));await tick();assert.equal($('url').value,'https://example.com');assert.equal(sent.length,0);
 let finish;state.reply=new Promise(resolve=>{finish=resolve;});submit();
 assert.equal($('check').disabled,true);assert.equal($('status').textContent,'Checking link…');assert.equal($('check-label').textContent,'Checking link…');
 finish({result:assessment()});await tick();await tick();
 assert.equal($('result').hidden,false);assert.equal($('input-view').hidden,true);assert.equal($('probability').textContent,'26.8%');
 assert.equal($('risk').textContent,'low risk');assert.equal($('score-fill').style.width,'26.8%');
 assert.equal($('score').getAttribute('aria-valuenow'),'26.8');assert.match($('safety').textContent,/does not guarantee/);
 assert.equal($('no-characteristics').hidden,false);assert.match($('no-characteristics').textContent,/No unusual URL/);
 $('another').dispatchEvent(new window.Event('click'));assert.equal($('input-view').hidden,false);assert.equal($('result').hidden,true);assert.equal($('url').value,'');assert.equal($('check').disabled,false);
 assert.deepEqual(opened,[]);
});
test('malicious result, many indicators and long URL are inert; retained URL can be expanded',async()=>{
 const {document,window,state,$,load}=await setup();await load();
 const url='https://example.com/'+ 'a'.repeat(7800) + '<img src=x onerror=alert(1)>';
 const indicators=Array.from({length:30},(_,i)=>`Indicator ${i}: <img src="https://forbidden.example">`);
 state.reply={result:assessment({url,prediction:'malicious',risk_level:'elevated',malicious_probability:.632,observed_characteristics:indicators})};
 $('url').value='https://example.com';$('checker').dispatchEvent(new window.Event('submit',{cancelable:true}));await tick();
 assert.equal($('verdict').textContent,'Potentially malicious link detected');assert.equal($('risk').textContent,'elevated risk');assert.equal($('probability').textContent,'63.2%');
 assert.match($('safety').textContent,/Avoid opening/);assert.equal($('full-url').textContent,url);assert.equal($('checked-url').textContent,url);
 assert.equal($('characteristics').children.length,30);assert.equal($('result').querySelectorAll('img,iframe,a').length,0);
 assert.equal($('no-characteristics').hidden,true);assert.match(document.querySelector('.disclaimer').textContent,/not causal explanations/);
 const css=await readFile(new URL('../popup.css',import.meta.url),'utf8');assert.match(css,/text-overflow: ellipsis/);assert.match(css,/overflow-wrap: anywhere/);assert.match(css,/max-height: 125px/);
});
test('auth-only sign-in state preserves the URL and trusted login destination; service errors hide internals',async()=>{
 const {document,window,opened,state,$,load}=await setup();await load();
 $('url').value='https://example.com';state.reply={error:{code:'auth',message:'internal session details'}};
 $('checker').dispatchEvent(new window.Event('submit',{cancelable:true}));await tick();
 assert.equal($('auth-state').hidden,false);assert.equal($('auth-title').textContent,'Sign in required');assert.equal($('input-view').hidden,true);assert.equal($('error').hidden,true);
 $('sign-in').dispatchEvent(new window.Event('click'));await tick();assert.deepEqual(opened,[{url:'https://nurtureshield-backend.onrender.com/sign-in'}]);
 $('auth-retry').dispatchEvent(new window.Event('click'));assert.equal($('auth-state').hidden,true);assert.equal($('input-view').hidden,false);assert.equal($('url').value,'https://example.com');
 for(const code of ['network','service','forbidden']){
  state.reply={error:{code,message:'Server: http://localhost:3000 Extension ID: private'}};
  $('checker').dispatchEvent(new window.Event('submit',{cancelable:true}));await tick();
  assert.equal($('error').hidden,false);assert.equal($('auth-state').hidden,true);assert.doesNotMatch($('error').textContent,/localhost|Extension ID|private/);assert.equal($('check').disabled,false);
 }
 assert.doesNotMatch(document.body.textContent,/localhost|Extension ID|8,192/);
});
test('right-click result job uses the same redesigned result and can return to input',async()=>{
 const {window,state,$,sent,load}=await setup('?job=context-result');
 state.reply={job:{id:'context-result',url:'https://example.com',createdAt:Date.now(),phase:'done',result:assessment()}};
 await load();await tick();assert.equal(sent[0].type,'job');assert.equal(sent[0].id,'context-result');assert.equal($('result').hidden,false);assert.equal($('risk').textContent,'low risk');
 $('another').dispatchEvent(new window.Event('click'));assert.equal($('input-view').hidden,false);assert.equal($('result').hidden,true);
});
