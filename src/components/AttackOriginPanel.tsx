import {useMemo} from 'react'
import ReactFlow,{Background,Controls,MarkerType,Position,type Edge,type Node} from 'reactflow'
import type {AttackOriginAssessment,AttackOriginTrace,EvidenceRecord,OriginNodeState} from '../types'
import {Icon} from './Icons'

const stateLabels:Record<OriginNodeState,string>={suspect:'Candidate', 'suspected-origin':'Suspected origin','potential-victim':'Potential victim','suspected-compromised-device':'Suspected compromised device','confirmed-evidence':'Confirmed evidence','likely-origin':'Likely origin',unknown:'Unknown'}
const strengthLabels={confirmed:'Confirmed evidence',strong:'Strong indicator',suspected:'Suspected',unknown:'Unknown'}
const statusLabels={
  'investigation-in-progress':'Investigation in progress',
  'likely-origin':'Likely origin identified',
  inconclusive:'Inconclusive',
  unknown:'Unknown',
}

function TraceGraph({trace}:{trace:AttackOriginTrace}){
  const {nodes,edges}=useMemo(()=>{
    const nodes:Node[]=trace.nodes.map((node,index)=>({id:node.id,position:{x:95,y:index*105},sourcePosition:Position.Bottom,targetPosition:Position.Top,data:{label:<div className={`origin-graph-node origin-state-${node.state}`}><span>{stateLabels[node.state]}</span><strong>{node.label}</strong>{node.detail&&<small>{node.detail}</small>}</div>}}))
    const edges:Edge[]=trace.edges.map(edge=>({id:edge.id,source:edge.source,target:edge.target,label:edge.label,labelStyle:{fill:'#98a8bb',fontSize:9,fontFamily:'DM Mono'},labelBgStyle:{fill:'#101824',fillOpacity:.95},animated:false,style:{stroke:'#46bdc5',strokeWidth:1.5},markerEnd:{type:MarkerType.ArrowClosed,color:'#46bdc5'}}))
    return{nodes,edges}
  },[trace])
  if(!nodes.length)return <div className="origin-empty">The backend returned no trace nodes for this suspect.</div>
  return <div className="origin-flow-host" aria-label="Backward attack-origin investigation graph"><ReactFlow nodes={nodes} edges={edges} fitView fitViewOptions={{padding:.2}} minZoom={.25} maxZoom={1.2} nodesDraggable={false} nodesConnectable={false} proOptions={{hideAttribution:true}}><Background color="#263545" gap={22} size={1}/><Controls showInteractive={false}/></ReactFlow></div>
}

function timeLabel(value:string){const date=new Date(value);return Number.isNaN(date.getTime())?value:date.toLocaleString(undefined,{month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZone:'UTC',timeZoneName:'short'})}

export default function AttackOriginPanel({assessment,evidence,trace,isSynthetic,loading,traceLoading,error,onTraceBack}:{assessment:AttackOriginAssessment|null;evidence:EvidenceRecord[];trace:AttackOriginTrace|null;isSynthetic:boolean;loading:boolean;traceLoading:boolean;error:string;onTraceBack:()=>void}){
  const confidence=assessment?.confidence?.score
  const hasConfidence=typeof confidence==='number'&&Number.isFinite(confidence)&&confidence>=0&&confidence<=1
  if(loading)return <div className="origin-empty" role="status">Loading origin assessment and evidence…</div>
  return <section className="origin-panel" aria-label="Attack origin evidence">
    {error&&<div className="inline-error" role="alert">{error}</div>}
    <div className="origin-summary">
      <div className="origin-assessment-copy"><span className="origin-eyebrow">ATTACK ORIGIN</span><h3>{statusLabels[assessment?.status??'unknown']}</h3><div className="origin-suspect-line"><span>Candidate entity</span><strong>{assessment?.suspect?.label??'Unknown'}</strong>{assessment?.suspect&&<em>{stateLabels[assessment.suspect.state]}</em>}</div><p>{assessment?.suspect?.reason??assessment?.summary??'No origin assessment was returned. Attacker identity could not be conclusively determined.'}</p><button className="trace-back-button" onClick={onTraceBack} disabled={!assessment?.suspect||traceLoading}>{traceLoading?<span className="spinner"/>:<Icon name="nodes" width={15} height={15}/>} {traceLoading?'Tracing…':'Trace Back'}</button></div>
      <div className="origin-confidence"><span>CONFIDENCE</span><strong>{hasConfidence?`${Math.round(confidence!*100)}%`:'Unknown'}</strong><small>{assessment?.confidence?.label??(isSynthetic?'No demo score is supplied.':'No confidence score returned by the backend.')}</small>{assessment?.likely_origin&&<div className="likely-origin"><span>LIKELY ORIGIN</span><strong>{assessment.likely_origin.label}</strong><small>{assessment.likely_origin.kind}</small></div>}</div>
    </div>
    {isSynthetic&&<div className="demo-auth-note">Synthetic demo data only. This is not real incident evidence or human-attacker attribution.</div>}
    <div className="origin-section-heading"><div><span className="origin-eyebrow">BACKWARD INVESTIGATION</span><h3>Trace supporting evidence</h3></div><span className="origin-count">{evidence.length} EVIDENCE ITEMS</span></div>
    {trace?<TraceGraph trace={trace}/>:<div className="origin-graph-prompt"><Icon name="nodes" width={17} height={17}/><span>Run Trace Back to load the investigation graph returned for this suspect.</span></div>}
    <div className="origin-section-heading origin-evidence-heading"><div><span className="origin-eyebrow">CORRELATED TELEMETRY</span><h3>Evidence timeline</h3></div><span className="origin-legend"><i className="legend-confirmed"/>Confirmed <i className="legend-strong"/>Strong <i className="legend-suspected"/>Suspected <i className="legend-unknown"/>Unknown</span></div>
    {evidence.length? <div className="origin-evidence-list">{evidence.map(item=><article className="origin-evidence-item" key={item.id}><div className="origin-evidence-time">{timeLabel(item.timestamp)}</div><div className="origin-evidence-main"><div className="origin-evidence-title"><strong>{item.event_type}</strong><span className={`evidence-strength strength-${item.strength}`}><i/>{strengthLabels[item.strength]}</span></div><div className="origin-evidence-details"><span><b>Source</b>{item.source??'Unknown'}</span><span><b>Destination</b>{item.destination??'Unknown'}</span><span><b>Device</b>{item.device??'Unknown'}</span><span><b>User</b>{item.user??'Unknown'}</span><span><b>IP</b>{item.ip??'Unknown'}</span></div><p>{item.reason}</p></div></article>)}</div>:<div className="origin-empty">No evidence was returned for this case. Attacker identity could not be conclusively determined.</div>}
    <div className="origin-attribution-warning"><span>!</span><p>TraceX estimates attack origin from available evidence. It does not guarantee identification of the human attacker.{assessment?.attribution_confirmed&&' The backend marked this origin attribution as confirmed; that does not identify a human without supporting identity evidence.'}</p></div>
  </section>
}
