import {useState,type FormEvent} from 'react'
import axios from 'axios'
import {Navigate,useLocation,useNavigate} from 'react-router-dom'
import Brand from '../components/Brand'
import {isMockMode} from '../api/client'
import {useAuth} from '../auth/AuthContext'

type LoginLocationState={from?:string;sessionExpired?:boolean;loggedOut?:boolean}

export default function LoginPage(){
  const navigate=useNavigate(),location=useLocation(),{status,login,sessionExpired:contextSessionExpired}=useAuth()
  const state=location.state as LoginLocationState|null
  const [email,setEmail]=useState(''),[password,setPassword]=useState(''),[showPassword,setShowPassword]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('')
  if(status==='authenticated')return <Navigate to={state?.from??'/cases'} replace/>

  async function submit(event:FormEvent){
    event.preventDefault();setError('')
    if(status==='loading'){setError('Checking the current session. Try again in a moment.');return}
    if(!email.trim()||!password){setError('Enter your email and password to continue.');return}
    setBusy(true)
    try{await login(email,password);navigate(state?.from??'/cases',{replace:true})}
    catch(reason){setError(axios.isAxiosError(reason)&&reason.response?.status===401?'Email or password was not accepted.':axios.isAxiosError(reason)&&reason.response?.status===422?'Enter a valid email and a password of at least 8 characters.':reason instanceof Error&&reason.message.includes('not configured')?reason.message:'Unable to reach the TraceX authentication service. Check the backend connection and try again.')}
    finally{setBusy(false)}
  }

  return <div className="login-page"><div className="login-glow login-glow-a"/><div className="login-glow login-glow-b"/><div className="login-nav"><Brand/><span>AI-POWERED ATTACK PATH AND ROOT-CAUSE INVESTIGATOR</span></div><div className="login-card"><div className="login-emblem"><Brand compact/></div><div className="panel-eyebrow">WELCOME BACK</div><h1>See the whole<br/><span>attack story.</span></h1><p>Sign in to investigate identity threats across your environment.</p>{(state?.sessionExpired||contextSessionExpired)&&<div className="session-message" role="status">Your session has ended or expired. Sign in again to continue.</div>}{state?.loggedOut&&<div className="session-message" role="status">You have been signed out.</div>}{isMockMode&&<div className="demo-auth-note">Controlled synthetic data may be shown after sign-in. Authentication is still validated by the TraceX backend.</div>}<form onSubmit={submit}><label htmlFor="email">Email</label><input id="email" type="email" placeholder="you@company.com" value={email} onChange={event=>setEmail(event.target.value)} autoComplete="username" required/><label htmlFor="password">Password</label><div className="password-field"><input id="password" type={showPassword?'text':'password'} placeholder="Enter your password" value={password} onChange={event=>setPassword(event.target.value)} autoComplete="current-password" required minLength={8}/><button type="button" className="password-toggle" onClick={()=>setShowPassword(value=>!value)} aria-label={showPassword?'Hide password':'Show password'}>{showPassword?'Hide':'Show'}</button></div>{error&&<div className="login-error" role="alert">{error}</div>}<button className="login-submit" disabled={busy||status==='loading'}>{busy?'Signing in…':status==='loading'?'Checking session…':'Sign In'} {!busy&&status!=='loading'&&<span>→</span>}</button></form><div className="login-foot"><span className="secure-dot"/> Session managed by the TraceX backend.</div></div><div className="login-bottom"><span>© 2026 TraceX Security</span><span>Privacy&nbsp;&nbsp; · &nbsp;&nbsp;Support</span></div></div>
}
