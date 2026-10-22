import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
const root=new URL('../',import.meta.url);
test('least-privilege MV3 module has only local resources and no ML artifacts',async()=>{
 const manifest=JSON.parse(await readFile(new URL('manifest.json',root),'utf8'));
 assert.equal(manifest.manifest_version,3);
 assert.deepEqual(manifest.permissions.sort(),['activeTab','contextMenus','storage']);
 assert.deepEqual(manifest.host_permissions,['https://nurtureshield-backend.onrender.com/*']);
 assert.equal(manifest.content_scripts,undefined);assert.equal(manifest.externally_connectable,undefined);
 assert.equal(manifest.content_security_policy.extension_pages.includes('connect-src https://nurtureshield-backend.onrender.com;'),true);
 for(const path of ['popup.html','popup.css','popup.js',manifest.background.service_worker,...Object.values(manifest.icons)])assert.ok((await readFile(new URL(path,root))).length);
 const names=(await readdir(root,{recursive:true})).filter(name=>!name.startsWith('node_modules/'));assert.equal(names.some(name=>/\.(joblib|ipynb|csv|pkl|py)$/.test(name)||name.endsWith('final_model_config.json')),false);
 const popup=await readFile(new URL('popup.js',root),'utf8');assert.equal(/innerHTML|outerHTML|insertAdjacentHTML/.test(popup),false);
 const html=await readFile(new URL('popup.html',root),'utf8');assert.equal(/<iframe|https?:\/\//.test(html),false);
});
