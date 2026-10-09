import axios from 'axios'
import type {AttackPath,AttackOriginAssessment,AttackOriginTrace,BlastRadius,CaseIntake,CaseSummary,EventRecord,EvidenceRecord,IntakeEvidence,Remediation,RootCause,VerificationResult,AuthSession} from '../types'
const mock=import.meta.env.VITE_USE_MOCK==='true'
const backendUrl=import.meta.env.VITE_API_BASE_URL?.trim()
const api=axios.create({baseURL:mock?'/mock-api':backendUrl||'http://127.0.0.1:8000',timeout:10000,withCredentials:true})
const authApi=axios.create({baseURL:backendUrl||'http://127.0.0.1:8000',timeout:10000,withCredentials:true})
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
