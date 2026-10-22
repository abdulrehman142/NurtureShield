import test from 'node:test';
import assert from 'node:assert/strict';
import { displayRisk, displayError } from '../presentation.js';
test('UI bands align to server classification without altering probability or decision',()=>{
 for(const [p,prediction,expected] of [[0,'legitimate','low'],[.268,'legitimate','low'],[.29999,'legitimate','low'],[.3,'malicious','moderate'],[.49999,'malicious','moderate'],[.5,'malicious','elevated'],[.79999,'malicious','elevated'],[.8,'malicious','high'],[1,'malicious','high']]){
  const result=Object.freeze({prediction,malicious_probability:p,risk_level:'moderate'});
  assert.equal(displayRisk(result),expected);assert.equal(result.malicious_probability,p);assert.equal(result.prediction,prediction);
 }
});
test('all error messages are presentation-only and omit technical API details',()=>{
 for(const code of ['auth','forbidden','network','service','response','timeout','rate','expired','validation','unknown'])assert.doesNotMatch(displayError({code,message:'localhost /secret extension ID'}),/localhost|\/secret|extension ID/);
});
