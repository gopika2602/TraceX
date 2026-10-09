import {useEffect,useMemo,useRef,useState} from 'react'
import {useNavigate} from 'react-router-dom'
import {getCases,isMockMode,loadControlledTestDataset} from '../api/client'
import type {CaseSummary,Severity} from '../types'
import {Icon} from '../components/Icons'
import NewInvestigationButton from '../components/NewInvestigationButton'

const severities:('all'|Severity)[]=['all','critical','high','medium','low']

export default function CasesPage(){
  const[cases,setCases]=useState<CaseSummary[]>([])
  const[statusFilter,setStatusFilter]=useState('All investigations')
  const[severityFilter,setSeverityFilter]=useState<'all'|Severity>('all')
  const[search,setSearch]=useState('')
  const[searchOpen,setSearchOpen]=useState(false)
  const[filtersOpen,setFiltersOpen]=useState(false)
  const[loadError,setLoadError]=useState(false)
  const[loading,setLoading]=useState(true)
  const[datasetBusy,setDatasetBusy]=useState(false)
  const[datasetMessage,setDatasetMessage]=useState('')
  const searchInput=useRef<HTMLInputElement>(null)
  const navigate=useNavigate()

  const refreshCases=()=>getCases().then(items=>{setCases(items);setLoadError(false)}).catch(()=>{setCases([]);setLoadError(true)}).finally(()=>setLoading(false))
  useEffect(()=>{let active=true;void getCases().then(items=>{if(active){setCases(items);setLoadError(false)}}).catch(()=>{if(active){setCases([]);setLoadError(true)}}).finally(()=>{if(active)setLoading(false)});return()=>{active=false}},[])
  const handleLoadDataset=async()=>{setDatasetBusy(true);setDatasetMessage('');try{const result=await loadControlledTestDataset();setDatasetMessage(`Controlled test dataset loaded (${result.event_count} events). Refreshing investigations…`);await refreshCases()}catch(error){setDatasetMessage(error instanceof Error?error.message:'The controlled dataset could not be loaded.')}finally{setDatasetBusy(false)}}
  useEffect(()=>{if(searchOpen)searchInput.current?.focus()},[searchOpen])

  const visible=useMemo(()=>cases.filter(item=>{
    const matchesStatus=statusFilter==='All investigations'||(statusFilter==='Open'?item.status!=='Resolved':item.status===statusFilter)
    const matchesSeverity=severityFilter==='all'||item.severity===severityFilter
    const query=search.trim().toLowerCase()
    const matchesSearch=!query||[item.id,item.title,item.identity,item.source,item.status].some(value=>value.toLowerCase().includes(query))
    return matchesStatus&&matchesSeverity&&matchesSearch
  }),[cases,statusFilter,severityFilter,search])
  const activeFilters=(statusFilter==='All investigations'?0:1)+(severityFilter==='all'?0:1)

  return <div className="cases-page">
    <div className="page-heading"><div><div className="panel-eyebrow">THREAT OPERATIONS / CASES</div><h1>Investigations <span className="heading-count">{cases.length.toString().padStart(2,'0')}</span></h1><p>Identity threats detected across your environment.</p></div><NewInvestigationButton/></div>{(isMockMode||cases.some(item=>item.synthetic))&&<div className="demo-auth-note">Controlled Test Dataset — synthetic records for UI review. {isMockMode?'Disable mock mode to load backend investigations.':'Backend analysis uses the controlled synthetic dataset.'}</div>}
    <div className="case-summary-grid"><div className="summary-card"><span>OPEN INVESTIGATIONS</span><strong>{cases.filter(c=>c.status!=='Resolved').length.toString().padStart(2,'0')}</strong><small>Count from the loaded case list</small></div><div className="summary-card"><span>CRITICAL SEVERITY</span><strong className="critical-text">{cases.filter(c=>c.severity==='critical').length.toString().padStart(2,'0')}</strong><small>Count from the loaded case list</small></div><div className="summary-card"><span>RESOLVED INVESTIGATIONS</span><strong>{cases.filter(c=>c.status==='Resolved').length.toString().padStart(2,'0')}</strong><small>Count from the loaded case list</small></div></div>
    <div className="case-toolbar"><div className="case-filter-tabs">{['All investigations','Open','Resolved'].map(option=><button type="button" key={option} className={statusFilter===option?'selected':''} onClick={()=>setStatusFilter(option)}>{option}{option==='All investigations'&&<span>{cases.length}</span>}</button>)}</div><div className="case-tool-actions">
      <div className="case-search-control">{searchOpen?<><Icon name="search" width={15} height={15}/><input ref={searchInput} className="case-search-input" value={search} onChange={event=>setSearch(event.target.value)} onKeyDown={event=>{if(event.key==='Escape'){setSearch('');setSearchOpen(false)}}} placeholder="Search cases" aria-label="Search investigations"/><button type="button" className="popover-close" onClick={()=>{setSearch('');setSearchOpen(false)}} aria-label="Close search">×</button></>:<button type="button" className="toolbar-search" onClick={()=>setSearchOpen(true)}><Icon name="search" width={15} height={15}/> Search cases</button>}</div>
      <div className="filter-control"><button type="button" className="filter-button" aria-expanded={filtersOpen} aria-controls="case-filter-menu" onClick={()=>setFiltersOpen(value=>!value)}><Icon name="filter" width={15} height={15}/> Filters{activeFilters>0&&<i>{activeFilters}</i>}</button>{filtersOpen&&<div className="control-popover filter-popover" id="case-filter-menu" role="group" aria-label="Filter investigations"><label htmlFor="severity-filter">Severity</label><select id="severity-filter" value={severityFilter} onChange={event=>setSeverityFilter(event.target.value as 'all'|Severity)}>{severities.map(value=><option key={value} value={value}>{value==='all'?'All severities':value[0].toUpperCase()+value.slice(1)}</option>)}</select><button type="button" className="clear-filter-button" onClick={()=>{setSeverityFilter('all');setStatusFilter('All investigations')}}>Clear filters</button></div>}</div>
    </div></div>
    {loadError&&<div className="inline-error" role="alert">Investigations could not be loaded. <button type="button" onClick={()=>{setLoading(true);void refreshCases()}}>Retry</button></div>}
    {datasetMessage&&<div className={datasetMessage.includes('could not')||datasetMessage.includes('requires')?'inline-error':'demo-auth-note'} role="status">{datasetMessage}</div>}
    {cases.length===0&&!isMockMode&&!loading&&!loadError&&<div className="demo-auth-note">No investigations are available. Load the controlled test dataset or connect a source dataset to begin.<button type="button" disabled={datasetBusy} onClick={()=>void handleLoadDataset()}>{datasetBusy?'Loading dataset…':'Load Controlled Test Dataset'}</button></div>}
    <div className="table-wrap case-table-wrap"><table className="case-table"><thead><tr><th>CASE</th><th>IDENTITY</th><th>SEVERITY</th><th>STATUS</th><th>DETECTED</th><th>SOURCE</th><th/></tr></thead><tbody>{visible.map(item=><tr key={item.id} tabIndex={0} onClick={()=>navigate(`/cases/${item.id}`)} onKeyDown={event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();navigate(`/cases/${item.id}`)}}}><td><span className="case-id">{item.id}</span><strong>{item.title}</strong></td><td><span className="case-identity"><span className="identity-avatar">{item.identity.slice(0,1).toUpperCase()}</span>{item.identity}</span></td><td><span className={`severity severity-${item.severity}`}><i/>{item.severity}</span></td><td><span className={`case-status ${item.status==='Investigating'?'status-investigating':item.status==='Contained'?'status-contained':item.status==='Draft'?'status-draft':'status-resolved'}`}><i/>{item.status}</span></td><td className="mono case-date">{item.detected}</td><td>{item.source}</td><td><Icon name="chevron" width={15} height={15}/></td></tr>)}</tbody></table>{loading?<div className="empty-state">Loading investigations…</div>:visible.length===0&&<div className="empty-state">{cases.length===0?'No investigations are available.':'No investigations match these filters.'}</div>}</div>
    <div className="case-table-footer">Showing <b>{visible.length}</b> of <b>{cases.length}</b> investigations</div>
  </div>
}
