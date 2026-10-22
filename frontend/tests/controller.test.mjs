import test from 'node:test';
import assert from 'node:assert/strict';
import { createController, MENU_ID } from '../controller.js';
import { ShieldError } from '../api.js';
export function fakeBrowser() {
  const stored={}; const opened=[]; const menus=[];
  const browser={
    runtime:{id:'a'.repeat(32),getURL:path=>`chrome-extension://${'a'.repeat(32)}/${path}`},
    contextMenus:{removeAll:async()=>{menus.length=0;},create:menu=>menus.push(menu)},
    tabs:{create:async tab=>{opened.push(tab);return tab;}},
    storage:{session:{get:async key=>key===null?{...stored}:{[key]:stored[key]},set:async entries=>Object.assign(stored,entries),remove:async keys=>{for(const key of [].concat(keys))delete stored[key];}}},
  };
  return {browser,stored,opened,menus};
}
const result={url:'example.com',prediction:'legitimate',malicious_probability:.268,risk_level:'moderate',observed_characteristics:[]};
test('context menu registers link-only and passes browser-provided URL without opening it',async()=>{
  const {browser,stored,opened,menus}=fakeBrowser();const calls=[];
  const controller=createController(browser,async url=>{calls.push(url);return {...result,url};},{makeId:()=> 'job-1'});
  await controller.install();assert.equal(menus[0].title,'Check link with NurtureShield');assert.deepEqual(menus[0].contexts,['link']);
  await controller.contextCheck({menuItemId:MENU_ID,linkUrl:'https://example.com',pageUrl:'https://unrelated.example'});
  assert.deepEqual(calls,['https://example.com']);assert.deepEqual(opened,[{url:browser.runtime.getURL('popup.html?job=job-1')}]);
  assert.equal(stored['shield-job:job-1'].phase,'done');assert.equal(stored['shield-job:job-1'].result.malicious_probability,.268);
});
test('failed analysis is presented; unknown menu ignored; invalid links never analyzed',async()=>{
  const {browser,stored}=fakeBrowser();let count=0;
  const controller=createController(browser,async()=>{count++;throw new ShieldError('auth','Sign in.');},{makeId:()=> 'job-2'});
  await controller.contextCheck({menuItemId:'unrelated',linkUrl:'https://example.com'});assert.equal(count,0);
  await controller.contextCheck({menuItemId:MENU_ID,linkUrl:'https://example.com'});assert.equal(stored['shield-job:job-2'].error.code,'auth');
  await controller.contextCheck({menuItemId:MENU_ID,linkUrl:'javascript:alert(1)'});assert.equal(count,1);assert.equal(stored['shield-job:job-2'].error.code,'validation');
});
test('messages accepted only from extension popup; no endpoint choice via messages',async()=>{
  const {browser}=fakeBrowser();let count=0;const controller=createController(browser,async()=>{count++;return result;});
  for(const sender of [{id:'x',url:browser.runtime.getURL('popup.html')},{id:browser.runtime.id,url:'https://example.com'},{id:browser.runtime.id,url:browser.runtime.getURL('other.html')}]) {
    assert.equal((await controller.message({type:'analyze',url:'example.com'},sender)).error.code,'forbidden');
  }
  assert.equal(count,0);
  const sender={id:browser.runtime.id,url:browser.runtime.getURL('popup.html')};
  assert.deepEqual(await controller.message({type:'analyze',url:'example.com'},sender),{result});assert.equal(count,1);
});
test('expired jobs removed; history bounded and session-only',async()=>{
  const {browser,stored}=fakeBrowser();
  for(let i=0;i<30;i++)stored[`shield-job:${i}`]={createdAt:1000+i};
  const controller=createController(browser,async()=>result,{now:()=>1100,makeId:()=> 'new'});
  await controller.contextCheck({menuItemId:MENU_ID,linkUrl:'https://example.com'});assert.equal(Object.keys(stored).length,20);
  stored['shield-job:old']={createdAt:-999999};
  const response=await controller.message({type:'job',id:'old'},{id:browser.runtime.id,url:browser.runtime.getURL('popup.html')});
  assert.equal(response.error.code,'expired');assert.equal(stored['shield-job:old'],undefined);
});
