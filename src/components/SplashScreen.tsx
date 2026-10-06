import { useEffect, useState } from 'react'

type SplashScreenProps = { onComplete: () => void }

export default function SplashScreen({ onComplete }: SplashScreenProps) {
  const [isLeaving, setIsLeaving] = useState(false)

  useEffect(() => {
    const previousOverflow = document.documentElement.style.overflow
    document.documentElement.style.overflow = 'hidden'
    const leaveTimer = window.setTimeout(() => setIsLeaving(true), 1_850)
    const finishTimer = window.setTimeout(onComplete, 2_250)
    const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)')
    const skipIntro = (event: MediaQueryListEvent) => {
      if (event.matches) onComplete()
    }

    motionPreference.addEventListener('change', skipIntro)
    return () => {
      window.clearTimeout(leaveTimer)
      window.clearTimeout(finishTimer)
      motionPreference.removeEventListener('change', skipIntro)
      document.documentElement.style.overflow = previousOverflow
    }
  }, [onComplete])

  return (
    <div
      className={`tracex-splash${isLeaving ? ' tracex-splash--leaving' : ''}`}
      role="status"
      aria-label="TraceX is tracing the attack path"
    >
      <div className="tracex-splash__halo" aria-hidden="true" />
      <div className="tracex-splash__stage" aria-hidden="true">
        <svg className="tracex-splash__route" viewBox="0 0 520 430" fill="none">
          <path className="tracex-splash__route-base" d="M47 238H145L198 191L239 211L294 158" />
          <path className="tracex-splash__route-trace" d="M47 238H145L198 191L239 211L294 158" />
          <circle className="tracex-splash__node tracex-splash__node--one" cx="47" cy="238" r="4" />
          <circle className="tracex-splash__node tracex-splash__node--two" cx="145" cy="238" r="4" />
          <circle className="tracex-splash__node tracex-splash__node--three" cx="198" cy="191" r="4" />
          <circle className="tracex-splash__node tracex-splash__node--four" cx="239" cy="211" r="4" />
          <circle className="tracex-splash__root-halo" cx="294" cy="158" r="13" />
          <circle className="tracex-splash__root" cx="294" cy="158" r="4.5" />
        </svg>
        <img className="tracex-splash__logo" src="/assets/tracex-logo.jpeg" alt="TraceX — AI-Powered Attack Path and Root-Cause Investigator" />
      </div>
      <div className="tracex-splash__sequence" aria-hidden="true">
        <span>TRACE</span><i /><span>INVESTIGATE</span><i /><span>ROOT CAUSE</span>
      </div>
    </div>
  )
}
