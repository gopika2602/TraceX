import {Navigate,Route,Routes} from 'react-router-dom'
import AppShell from './components/AppShell'
import LoginPage from './pages/LoginPage'
import CasesPage from './pages/CasesPage'
import CasePage from './pages/CasePage'
import ProtectedRoute from './components/ProtectedRoute'
export default function App(){return <Routes><Route path="/login" element={<LoginPage/>}/><Route element={<ProtectedRoute/>}><Route element={<AppShell/>}><Route index element={<Navigate to="/cases" replace/>}/><Route path="/cases" element={<CasesPage/>}/><Route path="/cases/:id" element={<CasePage/>}/></Route></Route><Route path="*" element={<Navigate to="/cases" replace/>}/></Routes>}
