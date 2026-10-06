import {Outlet} from 'react-router-dom'
import Sidebar from './Sidebar'
import Topbar from './Topbar'
export default function AppShell(){return <div className="app-shell"><Sidebar/><div className="main-shell"><Topbar/><main className="main-content"><Outlet/></main></div></div>}
