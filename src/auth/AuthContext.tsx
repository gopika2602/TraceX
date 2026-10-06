import axios from 'axios'
import {createContext,useCallback,useContext,useEffect,useMemo,useRef,useState,type ReactNode} from 'react'
import {useLocation,useNavigate} from 'react-router-dom'
import {getAuthSession,login as requestLogin,logout as requestLogout} from '../api/client'
import type {AuthSession} from '../types'

type AuthStatus='loading'|'authenticated'|'unauthenticated'
type AuthContextValue={status:AuthStatus;session:AuthSession|null;sessionExpired:boolean;login:(email:string,password:string)=>Promise<void>;logout:()=>Promise<void>;can:(permission:string)=>boolean;isAdmin:boolean}
const AuthContext=createContext<AuthContextValue|null>(null)

export function AuthProvider({children}:{children:ReactNode}){
  const [session,setSession]=useState<AuthSession|null>(null)
  const [status,setStatus]=useState<AuthStatus>('loading')
  const [sessionExpired,setSessionExpired]=useState(false)
  const navigate=useNavigate(),location=useLocation(),initialPath=useRef(location.pathname),navigateRef=useRef(navigate)
  navigateRef.current=navigate

  useEffect(()=>{
    let active=true
    const expire=()=>{setSession(null);setStatus('unauthenticated');setSessionExpired(true);sessionStorage.removeItem('tracex-demo-session');navigateRef.current('/login',{replace:true,state:{sessionExpired:true}})}
    window.addEventListener('tracex:session-expired',expire)
    void getAuthSession().then(value=>{if(active){setSession(value);setStatus(value?'authenticated':'unauthenticated')}}).catch(error=>{
      if(!active)return
      setSession(null);setStatus('unauthenticated')
      const expired=(axios.isAxiosError(error)&&error.response?.status===401&&error.response.data?.code==='SESSION_EXPIRED')||(error instanceof Error&&error.message==='SESSION_EXPIRED')
      setSessionExpired(expired)
      if(expired&&initialPath.current!=='/login')navigateRef.current('/login',{replace:true,state:{sessionExpired:true}})
    })
    return()=>{active=false;window.removeEventListener('tracex:session-expired',expire)}
  },[])

  useEffect(()=>{
    if(status!=='authenticated'||!session?.expires_at)return
    const expiresAt=Date.parse(session.expires_at)
    if(!Number.isFinite(expiresAt))return
    let timer=0
    const expireAtDeadline=()=>{
      const remaining=expiresAt-Date.now()
      if(remaining>2147480000){timer=window.setTimeout(expireAtDeadline,2147480000);return}
      if(remaining>0){timer=window.setTimeout(expireAtDeadline,remaining);return}
      setSession(null);setStatus('unauthenticated');setSessionExpired(true);sessionStorage.removeItem('tracex-demo-session');navigateRef.current('/login',{replace:true,state:{sessionExpired:true}})
    }
    expireAtDeadline()
    return()=>window.clearTimeout(timer)
  },[session?.expires_at,status])

  const login=useCallback(async(email:string,password:string)=>{const value=await requestLogin(email,password);setSession(value);setSessionExpired(false);setStatus('authenticated')},[])
  const logout=useCallback(async()=>{try{await requestLogout()}catch{/* Frontend access is cleared even when the API cannot be reached. */}finally{setSession(null);setSessionExpired(false);setStatus('unauthenticated');navigate('/login',{replace:true,state:{loggedOut:true}})}},[navigate])
  const can=useCallback((permission:string)=>session?.user.permissions?.includes(permission)??false,[session])
  const value=useMemo(()=>({status,session,sessionExpired,login,logout,can,isAdmin:session?.user.role==='admin'}),[status,session,sessionExpired,login,logout,can])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(){const value=useContext(AuthContext);if(!value)throw new Error('useAuth must be used within AuthProvider');return value}
