import {Navigate,Outlet,useLocation} from 'react-router-dom'
import {useAuth} from '../auth/AuthContext'

export default function ProtectedRoute(){
  const {status,sessionExpired}=useAuth(),location=useLocation()
  if(status==='loading')return <div className="auth-loading" role="status">Checking your TraceX session…</div>
  if(status!=='authenticated')return <Navigate to="/login" replace state={{from:`${location.pathname}${location.search}`,sessionExpired}}/>
  return <Outlet/>
}
