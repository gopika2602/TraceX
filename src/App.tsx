import {Navigate,Route,Routes} from 'react-router-dom'
import AppShell from './components/AppShell'
import LoginPage from './pages/LoginPage'
import CasesPage from './pages/CasesPage'
import CasePage from './pages/CasePage'
import CaseIntakePage from './pages/CaseIntakePage'
import ProtectedRoute from './components/ProtectedRoute'
import {apiConfigurationError} from './api/client'
export default function App(){if(apiConfigurationError)return <main className="api-configuration-error" role="alert"><div className="panel-eyebrow">DEPLOYMENT CONFIGURATION</div><h1>Backend connection required</h1><p>{apiConfigurationError}</p></main>;return <Routes><Route path="/login" element={<LoginPage/>}/><Route element={<ProtectedRoute/>}><Route element={<AppShell/>}><Route index element={<Navigate to="/cases" replace/>}/><Route path="/cases" element={<CasesPage/>}/><Route path="/investigations/new" element={<CaseIntakePage/>}/><Route path="/cases/:id" element={<CasePage/>}/></Route></Route><Route path="*" element={<Navigate to="/cases" replace/>}/></Routes>}
