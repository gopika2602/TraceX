import {useEffect,useState} from 'react'
import {NavLink,useLocation} from 'react-router-dom'
import Brand from './Brand'
import {Icon} from './Icons'
import {useAuth} from '../auth/AuthContext'
import {getBackendReadiness} from '../api/client'

export default function Sidebar(){
  const{session,logout}=useAuth(),location=useLocation(),user=session!.user,role=user.role==='admin'?'Admin':'Analyst',caseId=location.pathname.match(/^\/cases\/([^/]+)/)?.[1]
  const[backendReady,setBackendReady]=useState<boolean|null>(null)
  useEffect(()=>{let active=true;void getBackendReadiness().then(()=>{if(active)setBackendReady(true)}).catch(()=>{if(active)setBackendReady(false)});return()=>{active=false}},[])
  const selectedCase=caseId?`/cases/${encodeURIComponent(caseId)}`:'/cases'
  const links=[{label:'Overview',to:'/cases',icon:'grid',end:true},{label:'Investigations',to:selectedCase,icon:'pulse',end:false},{label:'Attack paths',to:caseId?`${selectedCase}?tab=path`:'/cases',icon:'nodes',end:false},{label:'Events',to:caseId?`${selectedCase}?tab=events`:'/cases',icon:'shield',end:false}]
  return <aside className="sidebar"><div className="sidebar-brand"><Brand/></div><div className="workspace-switch"><div className="workspace-glyph">T</div><div><small>WORKSPACE</small><strong>TraceX Workspace</strong></div></div><div className="nav-label">WORKSPACE</div><nav className="side-nav">{links.map(link=><NavLink key={link.label} to={link.to} end={link.end} className={({isActive})=>`side-link ${isActive?'active':''}`}><Icon name={link.icon}/><span>{link.label}</span></NavLink>)}</nav><div className="sidebar-spacer"/><div className="plan-card"><div className="plan-top"><span className={`plan-dot ${backendReady===false?'plan-dot-off':''}`}/> BACKEND + MONGODB <span className={`status-live ${backendReady===false?'status-off':''}`}>{backendReady===null?'CHECKING':backendReady?'READY':'UNAVAILABLE'}</span></div><small>{backendReady===true?'Readiness check passed':backendReady===false?'Check API URL and MongoDB connection':'Checking API and database…'}</small></div><div className="profile"><div className="avatar">{user.email.slice(0,2).toUpperCase()}</div><div className="profile-copy"><strong title={user.email}>{user.display_name??user.email}</strong><span>{role}</span></div><button className="logout-button" onClick={()=>void logout()} aria-label="Log out" title="Log out">Log out</button></div></aside>
}
