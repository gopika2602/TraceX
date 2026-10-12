import {Outlet} from 'react-router-dom'
import Sidebar from './Sidebar'
import Topbar from './Topbar'
import {apiConfigurationError} from '../api/client'
export default function AppShell(){return <div className="app-shell"><Sidebar/><div className="main-shell"><Topbar/>{apiConfigurationError&&<div className="shell-config-error" role="alert"><strong>Backend configuration required</strong><span>{apiConfigurationError}</span></div>}<main className="main-content"><Outlet/></main></div></div>}
