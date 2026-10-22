// No mocked predictions. Run against an isolated NurtureShield backend server.
import assert from 'node:assert/strict';
import { createApiClient } from '../api.js';
import { createController, MENU_ID } from '../controller.js';
const origin=process.env.SHIELD_TEST_ORIGIN;
if(!origin)throw Error('Set SHIELD_TEST_ORIGIN to an isolated local NurtureShield server.');
const extensionId='a'.repeat(32);
const extensionOrigin=`chrome-extension://${extensionId}`;
const calls=[];
const browserFetch=async(url,options)=>{
 assert.equal(url,`${origin}/api/v1/nurtureshield/analyze`,'Unexpected network destination');
 calls.push(url);
 return fetch(url,{...options,headers:{...options.headers,Origin:extensionOrigin}});
};
const analyze=createApiClient({origin,fetchImpl:browserFetch});
for(const [base,expected] of [['example.com',.268],['wikipedia.org',.276]]){
 const probabilities=[];
 for(const scheme of ['','http://','https://']){
  const result=await analyze(scheme+base);assert.equal(result.prediction,'legitimate');assert.ok(Math.abs(result.malicious_probability-expected)<.002);probabilities.push(result.malicious_probability);
 }
 assert.equal(new Set(probabilities).size,1);console.log(base,probabilities[0],'legitimate; all schemes identical');
}
const suspicious='https://secure-account-verify.example.com/login?account=verify&password=reset';
const direct=await analyze(suspicious);console.log('Synthetic suspicious URL',direct.malicious_probability,direct.prediction);
const stored={};const opened=[];
const browser={runtime:{id:extensionId,getURL:path=>`${extensionOrigin}/${path}`},storage:{session:{get:async key=>key===null?stored:{[key]:stored[key]},set:async values=>Object.assign(stored,values),remove:async keys=>{for(const key of [].concat(keys))delete stored[key];}}},tabs:{create:async tab=>opened.push(tab)}};
const controller=createController(browser,analyze,{makeId:()=> 'real-context-menu'});
await controller.contextCheck({menuItemId:MENU_ID,linkUrl:suspicious});
assert.deepEqual(stored['shield-job:real-context-menu'].result,direct);
assert.deepEqual(opened,[{url:`${extensionOrigin}/popup.html?job=real-context-menu`}]);
const presented=await controller.message({type:'job',id:'real-context-menu'},{id:extensionId,url:`${extensionOrigin}/popup.html?job=real-context-menu`});
assert.equal(presented.job.phase,'done');assert.deepEqual(presented.job.result,direct);
for(const url of ['', 'not a URL', 'https://'])await assert.rejects(analyze(url));
const real=await analyze('example.com');assert.equal(real.prediction,'legitimate');
console.log('Actual client + context-menu controller integration passed;',calls.length,'requests, only trusted analyze endpoint.');
console.log('Browser APIs simulated: Origin attachment, tab creation, storage. ML/API are real.');

// Execute the actual popup JavaScript in a DOM with real controller/API inference.
// Only browser APIs and browser-managed credentials are adapted, not ML results.
const {readFile}=await import('node:fs/promises');
const {parseHTML}=await import('linkedom');
const {document,window}=parseHTML(await readFile(new URL('../popup.html',import.meta.url),'utf8'));
globalThis.document=document;globalThis.location=new URL(`${extensionOrigin}/popup.html`);
browser.runtime.sendMessage=message=>controller.message(message,{id:extensionId,url:`${extensionOrigin}/popup.html`});
browser.tabs.query=async()=>[{url:'https://example.com'}];
browser.storage.onChanged={addListener(){}};
globalThis.chrome=browser;
await import('../popup.js?real-backend');
for(const [url,heading] of [['https://example.com','No malicious URL pattern detected'],[suspicious,'Potentially malicious link detected']]){
 const input=document.getElementById('url');input.value=url;input.dispatchEvent(new window.Event('input'));
 document.getElementById('checker').dispatchEvent(new window.Event('submit',{cancelable:true}));
 const deadline=Date.now()+30000;
 while(document.getElementById('check').disabled && Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,20));
 assert.equal(document.getElementById('result').hidden,false,document.getElementById('error').textContent);
 assert.equal(document.getElementById('verdict').textContent,heading);
 assert.equal(document.getElementById('result').querySelectorAll('a,img,iframe').length,0);
 console.log('Actual popup DOM + real backend:',document.getElementById('probability').textContent,heading);
}
