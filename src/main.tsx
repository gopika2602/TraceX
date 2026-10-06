import React from 'react'
import ReactDOM from 'react-dom/client'
import {BrowserRouter} from 'react-router-dom'
import 'reactflow/dist/style.css'
import './styles.css'
import App from './App'
import SplashScreen from './components/SplashScreen'
import {AuthProvider} from './auth/AuthContext'

function TraceXApp() {
  const [showSplash, setShowSplash] = React.useState(
    () => !window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  )

  return (
    <>
      <div className={showSplash ? 'app-under-splash' : undefined} aria-hidden={showSplash}>
        <BrowserRouter><AuthProvider><App /></AuthProvider></BrowserRouter>
      </div>
      {showSplash && <SplashScreen onComplete={() => setShowSplash(false)} />}
    </>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode><TraceXApp /></React.StrictMode>,
)
