import axios from 'axios'
import type {AttackPath,AttackOriginAssessment,AttackOriginTrace,BlastRadius,CaseSummary,EventRecord,EvidenceRecord,Remediation,RootCause,VerificationResult,AuthSession,AuthUser} from '../types'
const mock=import.meta.env.VITE_USE_MOCK==='true'
const api=axios.create({baseURL:mock?'/mock-api':import.meta.env.VITE_API_BASE_URL||'http://127.0.0.1:8000',timeout:10000,withCredentials:true})
api.interceptors.response.use(response=>response,error=>{const url=error.config?.url??'';if(error.response?.status===401&&!url.endsWith('/auth/login')&&!url.endsWith('/auth/session')&&!url.endsWith('/auth/logout')&&typeof window!=='undefined')window.dispatchEvent(new Event('tracex:session-expired'));return Promise.reject(error)})
async function get<T>(path:string){return (await api.get<T>(path)).data}
const mockSessionKey='tracex-demo-session'
export async function login(email:string,password:string):Promise<AuthSession>{if(mock){if(!email.trim()||!password)throw new Error('Enter your email and password.');const user=await get<AuthUser>('/auth-user.json');const session:AuthSession={user:{...user,email:email.trim()},expires_at:new Date(Date.now()+4*60*60*1000).toISOString()};sessionStorage.setItem(mockSessionKey,JSON.stringify(session));return session}return(await api.post<AuthSession>('/auth/login',{email,password})).data}
export async function getAuthSession():Promise<AuthSession|null>{if(mock){const stored=sessionStorage.getItem(mockSessionKey);if(!stored)return null;try{const session=JSON.parse(stored) as AuthSession;if(session.expires_at&&Date.parse(session.expires_at)<=Date.now()){sessionStorage.removeItem(mockSessionKey);throw new Error('SESSION_EXPIRED')}return session}catch(error){sessionStorage.removeItem(mockSessionKey);throw error}}return(await api.get<AuthSession>('/auth/session')).data}
export async function logout(){try{if(!mock)await api.post('/auth/logout')}finally{sessionStorage.removeItem(mockSessionKey);sessionStorage.removeItem('tracex-auth')}}
export const getCases=()=>get<CaseSummary[]>('/cases.json')
export const getEvents=()=>get<EventRecord[]>('/events.json')
export const getAttackPath=()=>get<AttackPath>('/attack-path.json')
export const getRootCause=()=>get<RootCause>('/root-cause.json')
export const getBlastRadius=()=>get<BlastRadius>('/blast-radius.json')
export const getRemediations=()=>get<Remediation[]>('/remediations.json')
export async function getAttackOrigin(caseId:string){return mock?get<AttackOriginAssessment>('/attack-origin.json'):get<AttackOriginAssessment>(`/cases/${encodeURIComponent(caseId)}/attack-origin`)}
export async function getEvidence(caseId:string){return mock?get<EvidenceRecord[]>('/evidence.json'):get<EvidenceRecord[]>(`/cases/${encodeURIComponent(caseId)}/evidence`)}
export async function getAttackOriginTrace(caseId:string,suspectId:string){return mock?get<AttackOriginTrace>('/attack-origin-trace.json'):get<AttackOriginTrace>(`/cases/${encodeURIComponent(caseId)}/attack-origin/trace?suspect_id=${encodeURIComponent(suspectId)}`)}
export async function applyRemediation(id:string){if(mock)return{id,status:'applied' as const};return(await api.post(`/remediations/${id}/apply`)).data as{id:string;status:'applied'}}
export async function runVerification(id:string){if(mock){const result=await get<VerificationResult>('/verification.json');if(id==='rem-2')return{...result,broken_at_step:6,after_allowed_steps:[1,2,3,4,5],after_blast_radius:3};if(id==='rem-3')return{...result,broken_at_step:3,after_allowed_steps:[1,2],after_blast_radius:2};return result}return(await api.post(`/remediations/${id}/verify`)).data as VerificationResult}
export const isMockMode=mock
