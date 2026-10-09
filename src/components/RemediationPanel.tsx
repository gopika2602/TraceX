import {useState} from 'react'
import axios from 'axios'
import {applyRemediation,runVerification} from '../api/client'
import type {Remediation,VerificationResult} from '../types'
import {Icon} from './Icons'

export default function RemediationPanel({caseId,initial,canApply}:{caseId:string;initial:Remediation[];canApply:boolean}){
  const[items,setItems]=useState(initial),[busy,setBusy]=useState<string|null>(null),[result,setResult]=useState<VerificationResult|null>(null),[error,setError]=useState('')
  async function remediate(item:Remediation){
    setBusy(item.id);setError('');setResult(null)
    let applied=false
    try{
      await applyRemediation(caseId,item.id)
      applied=true
      setItems(current=>current.map(row=>row.id===item.id?{...row,status:'applied'}:row))
      setResult(await runVerification(caseId,item.id))
    }catch(reason){
      setError(axios.isAxiosError(reason)&&reason.response?.status===403?'Your authenticated session does not have permission to apply this remediation.':axios.isAxiosError(reason)&&reason.response?.status===404?'This remediation or case was not found by the backend.':axios.isAxiosError(reason)&&reason.response?.status===409?'This case has no baseline environment to verify.':`The backend could not complete ${applied?'verification':'remediation'}. Check the case and backend status, then try again.`)
    }finally{setBusy(null)}
  }
  const resultTitle=result?.status==='PATH_BROKEN'?'Attack path blocked':result?.status==='PATH_STILL_OPEN'?'Attack path remains allowed':'Verification inconclusive'
  return <div className="remediation-page">
    <div className="remediation-intro"><div><div className="panel-eyebrow">CONTAINMENT PLAN</div><h2>Recommended actions</h2><p>Actions and verification are returned by the backend for case {caseId}.</p></div><span className="recommendation-count">{items.length} RECOMMENDATIONS</span></div>
    {error&&<div className="inline-error" role="alert">{error}</div>}{!canApply&&<div className="permission-note">Read only — this session does not include remediation permission. The backend enforces this restriction.</div>}
    {items.length===0?<div className="empty-state">The backend has no remediation recommendations for this case.</div>:<div className="remediation-list">{items.map((item,index)=><article className={`remediation-card ${item.status==='applied'?'is-applied':''}`} key={item.id}><div className="remediation-index">{String(index+1).padStart(2,'0')}</div><div className="remediation-copy"><div className="remediation-meta"><span className={`priority priority-${item.priority.toLowerCase()}`}><i/>{item.priority} PRIORITY</span><span className="remediation-id">{item.id}</span></div><h3>{item.title}</h3><p>{item.description}</p><div className="action-code"><span>ACTION</span><code>{item.action}</code></div><div className="remediation-bottom"><span><b>BREAKS AT</b> {item.expected_paths_broken.length?item.expected_paths_broken.map(step=>`STEP ${step}`).join(', '):'Engine did not identify a step'}</span><span><b>COLLATERAL</b> {item.collateral}</span></div></div>{canApply?<button type="button" className={`apply-button ${item.status==='applied'?'applied':''}`} onClick={()=>void remediate(item)} disabled={busy!==null||item.status==='applied'}>{busy===item.id?<span className="spinner"/>:item.status==='applied'?<><Icon name="check" width={15} height={15}/> Applied</>:'Apply action'}</button>:<span className="read-only-tag">VIEW ONLY</span>}</article>)}</div>}
    {result&&<section className={`verification-card ${result.status==='PATH_BROKEN'?'verified':'open'}`}><div className="verification-symbol"><Icon name={result.status==='PATH_BROKEN'?'check':'close'}/></div><div className="verification-copy"><div className="panel-eyebrow">BACKEND VERIFICATION · {result.status==='PATH_BROKEN'?'PASS':result.status==='PATH_STILL_OPEN'?'FAIL':'INCONCLUSIVE'}</div><h3>{resultTitle}</h3><p>{result.status==='PATH_BROKEN'?`The replay denied the attack sequence at observed step ${result.broken_at_step??'unknown'}.`:result.status==='PATH_STILL_OPEN'?'The backend replay did not find a denied transition; this remediation did not break the observed path.':'The engine could not map this case’s observed steps onto environment permissions, so it cannot verify the change.'}</p><div className="verify-stats"><span><b>{result.before_allowed_steps.length}</b> allowed before</span><span><b>{result.after_allowed_steps.length}</b> allowed after</span><span><b>{result.transition_count??'—'}</b> transitions replayed</span><span><b>{result.normal_access_preserved===null||result.normal_access_preserved===undefined?'Unknown':result.normal_access_preserved?'Yes':'No'}</b> unrelated access preserved</span><span><b>{result.before_blast_radius} → {result.after_blast_radius}</b> reachable resources</span></div><p className="verification-steps"><b>BEFORE — ALLOWED STEPS:</b> {result.before_allowed_steps.length?result.before_allowed_steps.join(', '):'None returned'}<br/><b>AFTER — ALLOWED STEPS:</b> {result.after_allowed_steps.length?result.after_allowed_steps.join(', '):'None returned'}</p></div></section>}
  </div>
}
