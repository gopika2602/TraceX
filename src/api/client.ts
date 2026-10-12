import axios from 'axios'
import type {AttackPath,AttackOriginAssessment,AttackOriginTrace,BlastRadius,CaseIntake,CaseSummary,EventRecord,EvidenceRecord,IntakeEvidence,Remediation,RootCause,VerificationResult,AuthSession} from '../types'
const mock=import.meta.env.DEV&&import.meta.env.VITE_USE_MOCK==='true'
const configuredBackendUrl=import.meta.env.VITE_API_BASE_URL?.trim()
const backendUrl=configuredBackendUrl||(import.meta.env.DEV?'http://127.0.0.1:8000':'')
export const apiConfigurationError=import.meta.env.PROD&&!configuredBackendUrl
  ?'TraceX is not connected to its backend. Set VITE_API_BASE_URL in the Vercel Production environment, then redeploy.'
  :import.meta.env.PROD&&import.meta.env.VITE_USE_MOCK==='true'
    ?'Mock data mode is disabled for hosted deployments. Set VITE_USE_MOCK=false in the Vercel Production environment, then redeploy.'
    :''
const api=axios.create({baseURL:mock?'/mock-api':backendUrl,timeout:10000,withCredentials:true})
const authApi=axios.create({baseURL:backendUrl,timeout:10000,withCredentials:true})
const requireBackendConfiguration=()=>{if(apiConfigurationError)throw new Error(apiConfigurationError)}
api.interceptors.request.use(config=>{requireBackendConfiguration();return config})
authApi.interceptors.request.use(config=>{requireBackendConfiguration();return config})
const handleUnauthorized=(response:any,error:any)=>{const url=error.config?.url??'';if(response?.status===401&&!url.endsWith('/auth/login')&&!url.endsWith('/auth/session')&&!url.endsWith('/auth/logout')&&typeof window!=='undefined')window.dispatchEvent(new Event('tracex:session-expired'));return Promise.reject(error)}
api.interceptors.response.use(response=>response,error=>handleUnauthorized(error.response,error))
authApi.interceptors.response.use(response=>response,error=>handleUnauthorized(error.response,error))
async function get<T>(path:string){return (await api.get<T>(path)).data}
function requireAuthBackend(){if(mock&&!backendUrl)throw new Error('Authentication backend is not configured. Set VITE_API_BASE_URL to the TraceX API URL.')}
export async function login(email:string,password:string):Promise<AuthSession>{requireAuthBackend();return(await authApi.post<AuthSession>('/auth/login',{email,password})).data}
export async function getAuthSession():Promise<AuthSession|null>{requireAuthBackend();return(await authApi.get<AuthSession>('/auth/session')).data}
export async function logout(){try{if(!mock||backendUrl)await authApi.post('/auth/logout')}finally{sessionStorage.removeItem('tracex-demo-session');sessionStorage.removeItem('tracex-auth')}}
export async function getBackendReadiness(){requireAuthBackend();return(await authApi.get<{status:string;database:string;engine:string}>('/health/ready')).data}
export async function getCases(){return get<CaseSummary[]>(mock?'/cases.json':'/cases')}
export async function getCase(caseId:string){if(mock){const cases=await getCases();const selected=cases.find(item=>item.id===caseId);if(!selected)throw new Error('This case is not part of the controlled test dataset.');return selected}return get<CaseSummary>(`/cases/${encodeURIComponent(caseId)}`)}
export async function loadControlledTestDataset(){if(mock)throw new Error('Loading a dataset requires the connected backend.');return(await api.post<{id:string;event_count:number;synthetic:boolean}>('/datasets/load-demo')).data}
export async function createCase():Promise<CaseSummary>{if(mock)throw new Error('Creating investigations requires the connected backend. Disable VITE_USE_MOCK and configure VITE_API_BASE_URL.');const response=await api.post<{case:CaseSummary}>('/cases');return response.data.case}
export async function submitCaseIntake(payload:CaseIntake){if(mock)throw new Error('Saving an investigation requires the connected backend.');return(await api.post<{case_id:string;case:CaseSummary;evidence_count:number;synthetic:boolean}>('/cases/intake',payload)).data}
export type ExtractionEvent=Omit<IntakeEvidence,'timestamp'>&{event_id:string;timestamp:string|null;confidence:number;extraction_method:string;verification_status:'unreviewed'|'approved'|'rejected';raw_event_reference:string;warnings:string[]}
export type ExtractionPreview={id:string;status:string;created_at:string;extraction_method:string;ai_provider:null;sources:{name:string;kind:string;size_bytes:number}[];events:ExtractionEvent[];warnings:string[]}
export async function previewExtraction(story:string,files:File[]){if(mock)throw new Error('Evidence extraction requires the connected backend.');const body=new FormData();body.append('story',story);for(const file of files)body.append('files',file);return(await api.post<ExtractionPreview>('/cases/extractions/preview',body,{headers:{'Content-Type':'multipart/form-data'},timeout:60000})).data}
export async function reviewExtraction(id:string,events:ExtractionEvent[]){return(await api.put<ExtractionPreview>(`/cases/extractions/${encodeURIComponent(id)}/review`,{events:events.map(event=>({event_id:event.event_id,status:event.verification_status,fields:{evidence_type:event.evidence_type,timestamp:event.timestamp,identity:event.identity,source_ip:event.source_ip,destination_ip:event.destination_ip,device_id:event.device_id,api_service:event.api_service,resource:event.resource,permission:event.permission,session_id:event.session_id,token_id:event.token_id,user_agent:event.user_agent,description:event.description}}))})).data}
export async function importExtraction(id:string,caseName:string){const body=new FormData();body.append('case_name',caseName);return(await api.post<{status:string;case_id:string;analysis_status:'analyzed'|'pending'}>(`/cases/extractions/${encodeURIComponent(id)}/import`,body)).data}
export async function updateCaseNotes(caseId:string,notes:string){return(await api.patch(`/cases/${encodeURIComponent(caseId)}/notes`,{notes})).data}
export async function getCollectedEvidence(caseId:string){return get<(IntakeEvidence&{id:string;event_id:string})[]>(`/cases/${encodeURIComponent(caseId)}/collected-evidence`)}
export async function analyzeCase(caseId:string){return(await api.post(`/cases/${encodeURIComponent(caseId)}/analyze`)).data as{case_id:string;status:string;event_count:number}}
export const getEvents=(caseId:string)=>get<EventRecord[]>(mock?'/events.json':`/cases/${encodeURIComponent(caseId)}/events`)
export const getAttackPath=(caseId:string)=>get<AttackPath>(mock?'/attack-path.json':`/cases/${encodeURIComponent(caseId)}/attack-path`)
export const getRootCause=(caseId:string)=>get<RootCause>(mock?'/root-cause.json':`/cases/${encodeURIComponent(caseId)}/root-cause`)
export const getBlastRadius=(caseId:string)=>get<BlastRadius>(mock?'/blast-radius.json':`/cases/${encodeURIComponent(caseId)}/blast-radius`)
export const getRemediations=(caseId:string)=>get<Remediation[]>(mock?'/remediations.json':`/cases/${encodeURIComponent(caseId)}/remediations`)
export async function getAttackOrigin(caseId:string){return mock?get<AttackOriginAssessment>('/attack-origin.json'):get<AttackOriginAssessment>(`/cases/${encodeURIComponent(caseId)}/attack-origin`)}
export async function getEvidence(caseId:string){return mock?get<EvidenceRecord[]>('/evidence.json'):get<EvidenceRecord[]>(`/cases/${encodeURIComponent(caseId)}/evidence`)}
export async function getAttackOriginTrace(caseId:string,suspectId:string){return mock?get<AttackOriginTrace>('/attack-origin-trace.json'):get<AttackOriginTrace>(`/cases/${encodeURIComponent(caseId)}/attack-origin/trace?suspect_id=${encodeURIComponent(suspectId)}`)}
export async function applyRemediation(caseId:string,id:string){if(mock)throw new Error('Applying remediation requires the connected backend.');return(await api.post(`/cases/${encodeURIComponent(caseId)}/remediations/${encodeURIComponent(id)}/apply`)).data as{id:string;status:'applied';environment_version:number}}
export async function runVerification(caseId:string,id:string){if(mock)throw new Error('Verification requires the connected backend.');return(await api.post(`/cases/${encodeURIComponent(caseId)}/verify`,null,{params:{remediation_id:id}})).data as VerificationResult}
export const isMockMode=mock
