import {useMemo,useState,type FormEvent} from 'react'
import {Link,useNavigate} from 'react-router-dom'
import axios from 'axios'
import {submitCaseIntake} from '../api/client'
import type {CaseIntake,IntakeEvidence} from '../types'

const newEvidence=():IntakeEvidence=>({evidence_type:'',timestamp:new Date(Date.now()-new Date().getTimezoneOffset()*60000).toISOString().slice(0,16)})
const fields:{key:keyof IntakeEvidence;label:string;type?:string;wide?:boolean}[]=[
  {key:'evidence_type',label:'Evidence type'}, {key:'timestamp',label:'Timestamp',type:'datetime-local'},
  {key:'source',label:'Source / collection method'}, {key:'source_ip',label:'Source IP'},
  {key:'destination_ip',label:'Destination IP'}, {key:'device_id',label:'Device ID'},
  {key:'identity',label:'User / identity'}, {key:'session_id',label:'Session ID'}, {key:'token_id',label:'Token ID'},
  {key:'permission',label:'Observed permission / action'}, {key:'resource',label:'Destination resource'},
  {key:'user_agent',label:'User-agent'}, {key:'process',label:'Process / execution'},
  {key:'authentication',label:'Authentication information'}, {key:'network_connection',label:'Network connection'},
  {key:'api_service',label:'API / application / service'}, {key:'description',label:'Evidence description',wide:true},
  {key:'investigator_notes',label:'Investigator note for this evidence',wide:true},
]

export default function CaseIntakePage(){
  const navigate=useNavigate()
  const[caseInfo,setCaseInfo]=useState({case_id:'',case_name:'',organization:'',incident_at:'',description:'',investigator_name:'',investigator_notes:''})
  const[draft,setDraft]=useState<IntakeEvidence>(newEvidence()),[evidence,setEvidence]=useState<IntakeEvidence[]>([]),[editing,setEditing]=useState<number|null>(null)
  const[query,setQuery]=useState(''),[environmentJson,setEnvironmentJson]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState('')
  const visible=useMemo(()=>evidence.map((record,index)=>({record,index})).filter(({record})=>Object.values(record).join(' ').toLowerCase().includes(query.trim().toLowerCase())).sort((a,b)=>Date.parse(a.record.timestamp)-Date.parse(b.record.timestamp)),[evidence,query])
  function setDraftField(key:keyof IntakeEvidence,value:string){setDraft(current=>({...current,[key]:value}))}
  function addEvidence(event?:FormEvent){event?.preventDefault();if(!draft.evidence_type.trim()){setError('Choose or enter an evidence type.');return}if(!draft.timestamp){setError('Add the evidence timestamp.');return}if(editing===null)setEvidence(current=>[...current,draft]);else setEvidence(current=>current.map((item,index)=>index===editing?draft:item));setDraft(newEvidence());setEditing(null);setError('')}
  function editEvidence(index:number){setDraft(evidence[index]);setEditing(index);window.scrollTo({top:0,behavior:'smooth'})}
  function deleteEvidence(index:number){setEvidence(current=>current.filter((_,itemIndex)=>itemIndex!==index));if(editing===index){setEditing(null);setDraft(newEvidence())}}
  async function saveCase(event:FormEvent){
    event.preventDefault();setError('')
    if(evidence.length===0){setError('Add at least one evidence record before saving.');return}
    let environment:CaseIntake['environment']
    if(environmentJson.trim()){
      try{
        const parsed:unknown=JSON.parse(environmentJson)
        if(!parsed||typeof parsed!=='object'||!Array.isArray((parsed as {nodes?:unknown}).nodes)||!Array.isArray((parsed as {edges?:unknown}).edges)){
          setError('The access graph must be a JSON object with nodes and edges arrays.');return
        }
        environment=parsed as CaseIntake['environment']
      }catch{setError('The access graph is not valid JSON. Correct it or clear the field to continue.');return}
    }
    setBusy(true)
    try{
      const payload:CaseIntake={...caseInfo,case_id:caseInfo.case_id||undefined,organization:caseInfo.organization||undefined,incident_at:caseInfo.incident_at?new Date(caseInfo.incident_at).toISOString():undefined,description:caseInfo.description||undefined,investigator_name:caseInfo.investigator_name||undefined,investigator_notes:caseInfo.investigator_notes||undefined,evidence,environment}
      const created=await submitCaseIntake(payload);navigate(`/cases/${created.case_id}?tab=evidence`,{replace:true})
    }catch(reason){
      const detail=axios.isAxiosError(reason)?reason.response?.data?.detail:undefined
      setError(typeof detail==='string'?detail:detail?.message??(reason instanceof Error?reason.message:'The case intake could not be saved. Check the backend connection and try again.'))
    }finally{setBusy(false)}
  }
  return <div className="intake-page">
    <div className="case-back"><Link to="/cases">← &nbsp;All investigations</Link><span>/</span><span>New investigation</span></div>
    <div className="page-heading intake-heading"><div><div className="panel-eyebrow">INVESTIGATION WORKSPACE / INTAKE</div><h1>New Investigation</h1><p>Record case context and evidence before running TraceX analysis.</p></div><span className="intake-step">01 / CASE INTAKE</span></div>
    <form onSubmit={saveCase}>
      <section className="intake-card"><div className="intake-section-title"><div><div className="panel-eyebrow">CASE INFORMATION</div><h2>Incident context</h2></div><span>Required fields are marked *</span></div>
        <div className="intake-fields"><label>Case ID<input value={caseInfo.case_id} onChange={e=>setCaseInfo({...caseInfo,case_id:e.target.value})} placeholder="Generated if left blank"/></label><label>Case name *<input required value={caseInfo.case_name} onChange={e=>setCaseInfo({...caseInfo,case_name:e.target.value})} placeholder="Short investigation title"/></label><label>Organization<input value={caseInfo.organization} onChange={e=>setCaseInfo({...caseInfo,organization:e.target.value})}/></label><label>Incident date and time<input type="datetime-local" value={caseInfo.incident_at} onChange={e=>setCaseInfo({...caseInfo,incident_at:e.target.value})}/></label><label>Investigator name<input value={caseInfo.investigator_name} onChange={e=>setCaseInfo({...caseInfo,investigator_name:e.target.value})}/></label><label className="intake-wide">Incident description<textarea rows={2} value={caseInfo.description} onChange={e=>setCaseInfo({...caseInfo,description:e.target.value})}/></label><label className="intake-wide"><span>INVESTIGATOR NOTE · CASE LEVEL</span><textarea rows={3} value={caseInfo.investigator_notes} onChange={e=>setCaseInfo({...caseInfo,investigator_notes:e.target.value})} placeholder="Your observations are stored separately from TraceX analysis."/></label></div>
      </section>
      <section className="intake-card"><div className="intake-section-title"><div><div className="panel-eyebrow">ENVIRONMENT CONTEXT</div><h2>Access graph</h2><p>Optional, but needed for evidence based blast radius and path verification.</p></div><span>AUTHORITATIVE POLICY DATA</span></div><label className="intake-environment-label">Environment graph JSON<textarea rows={8} spellCheck={false} value={environmentJson} onChange={event=>setEnvironmentJson(event.target.value)} placeholder={'{\n  "nodes": [{"id": "identity-1", "type": "identity"}, {"id": "token-1", "type": "token"}, {"id": "service-1", "type": "service"}],\n  "edges": [{"from": "identity-1", "to": "token-1", "permission": "use"}, {"from": "token-1", "to": "service-1", "permission": "read"}]\n}'} aria-describedby="environment-graph-help"/><span id="environment-graph-help" className="form-help">Format example only. Replace it with the actual access graph from your environment. Do not enter assumptions: without this graph, TraceX will report verification as unavailable when it cannot validate a policy path.</span></label></section>
      <section className="intake-card"><div className="intake-section-title"><div><div className="panel-eyebrow">EVIDENCE COLLECTION</div><h2>Evidence records</h2><p>Enter observations from your case. Optional fields can be left blank.</p></div><span>{evidence.length} RECORDS</span></div>
        <div className="evidence-entry"><h3>{editing===null?'Add evidence':'Edit evidence record'}</h3><div className="intake-fields">{fields.map(field=><label className={field.wide?'intake-wide':''} key={field.key}>{field.label}{field.key==='evidence_type'?<><input list="evidence-type-options" value={draft.evidence_type} onChange={e=>setDraftField(field.key,e.target.value)} required/><datalist id="evidence-type-options">{['new_device_login','session_reuse','anomalous_authentication','token_use','oauth_token_created','api_access','privilege_escalation','data_access','malicious_external_connection','mfa_success'].map(value=><option key={value} value={value}/>)}</datalist></>:field.wide?<textarea rows={field.key==='description'?2:3} value={String(draft[field.key]??'')} onChange={e=>setDraftField(field.key,e.target.value)}/>:<input type={field.type??'text'} required={field.key==='timestamp'} value={String(draft[field.key]??'')} onChange={e=>setDraftField(field.key,e.target.value)}/>}</label>)}</div><div className="evidence-entry-actions"><button type="button" className="quiet-button" onClick={()=>{setDraft(newEvidence());setEditing(null)}}>Clear</button><button type="button" className="case-primary" onClick={addEvidence}>{editing===null?'Add evidence record':'Save evidence changes'}</button></div></div>
        <div className="evidence-list-heading"><h3>Collected evidence</h3><div><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search evidence" aria-label="Search collected evidence"/><span>Sorted oldest first</span></div></div>
        {visible.length===0?<div className="intake-empty">No evidence collected yet.<br/>Add evidence to begin the investigation.</div>:<div className="table-wrap"><table className="intake-evidence-table"><thead><tr><th>TIMESTAMP</th><th>TYPE</th><th>IDENTITY</th><th>DEVICE</th><th>SOURCE</th><th>DESCRIPTION</th><th>STATUS</th><th/></tr></thead><tbody>{visible.map(({record,index})=><tr key={`${index}-${record.timestamp}`}><td>{new Date(record.timestamp).toLocaleString()}</td><td>{record.evidence_type}</td><td>{record.identity||'Unknown'}</td><td>{record.device_id||'Unknown'}</td><td>{record.source_ip||record.source||'Unknown'}</td><td>{record.description||'No description'}</td><td><span className="intake-pending">Collected</span></td><td><button type="button" className="intake-row-action" onClick={()=>editEvidence(index)}>Edit</button><button type="button" className="intake-row-action delete" onClick={()=>deleteEvidence(index)}>Delete</button></td></tr>)}</tbody></table></div>}
      </section>
      {error&&<div className="inline-error" role="alert">{error}</div>}
      <div className="intake-footer"><span>Save the case and evidence first. You can review the persisted records before running analysis.</span><button className="case-primary" disabled={busy||evidence.length===0}>{busy?'Saving case…':'Save case'}</button></div>
    </form>
  </div>
}
