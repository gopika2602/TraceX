import {createContext,useContext,useEffect,useMemo,useState,type ReactNode} from 'react'

type Theme='dark'|'light'
type ThemeContextValue={theme:Theme;toggleTheme:()=>void}
const ThemeContext=createContext<ThemeContextValue|null>(null)
function initialTheme():Theme{
  try{const saved=localStorage.getItem('tracex-theme');if(saved==='light'||saved==='dark')return saved}catch{/* Storage can be disabled; use the system preference. */}
  return window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'
}
export function ThemeProvider({children}:{children:ReactNode}){
  const[theme,setTheme]=useState<Theme>(initialTheme)
  useEffect(()=>{document.documentElement.dataset.theme=theme;try{localStorage.setItem('tracex-theme',theme)}catch{/* Keep the selected theme for this session. */}},[theme])
  const value=useMemo(()=>({theme,toggleTheme:()=>setTheme(current=>current==='dark'?'light':'dark')}),[theme])
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}
export function useTheme(){const value=useContext(ThemeContext);if(!value)throw new Error('useTheme must be used within ThemeProvider');return value}
