import { useEffect, useRef, useState, useCallback, memo } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import useAlertStore from '../../store/alertStore'

cytoscape.use(dagre)

/* ── Risk colour helper ────────────────────────────────────────────────────── */
function riskColor(score) {
  if (score > 0.8) return '#ef4444'   // critical — red
  if (score > 0.5) return '#f97316'   // high — orange
  if (score > 0.2) return '#eab308'   // medium — yellow
  return '#3b82f6'                     // low — blue
}

function riskBorder(score, compromised) {
  if (compromised) return '#ef4444'
  if (score > 0.8) return '#f87171'
  if (score > 0.5) return '#fb923c'
  return 'rgba(59,130,246,0.5)'
}

/* ── Cytoscape stylesheet ─────────────────────────────────────────────────── */
const CY_STYLE = [
  // ── Base node ──
  {
    selector: 'node',
    style: {
      'label': 'data(label)',
      'text-valign': 'bottom',
      'text-margin-y': 6,
      'font-size': 9,
      'font-family': "'Sora', monospace",
      'color': '#1e3a5f',
      'background-color': '#dbeafe',
      'border-width': 2,
      'border-color': 'rgba(59,130,246,0.4)',
      'width': 30,
      'height': 30,
      'transition-property': 'background-color, border-color, width, height',
      'transition-duration': '0.3s',
    },
  },
  // ── IP nodes → circle (default, no override needed) ──
  {
    selector: 'node[node_type="ip"]',
    style: {
      'shape': 'ellipse',
      // width/height driven by mapData in JS
    },
  },
  // ── Process nodes → diamond ──
  {
    selector: 'node[node_type="process"]',
    style: {
      'shape': 'diamond',
      'width': 32, 'height': 32,
    },
  },
  // ── User nodes → square ──
  {
    selector: 'node[node_type="user"]',
    style: {
      'shape': 'rectangle',
      'width': 30, 'height': 30,
      'corner-radius': 4,
    },
  },
  // ── Risk colors (applied via JS updateNodeStyles) ──
  // ── Compromised nodes ──
  {
    selector: 'node[?is_compromised]',
    style: {
      'border-width': 3.5,
      'border-color': '#ef4444',
      'border-opacity': 1,
    },
  },
  // ── Selected ──
  {
    selector: ':selected',
    style: {
      'border-color': '#8b5cf6',
      'border-width': 3,
      'shadow-blur': 12,
      'shadow-color': '#8b5cf6',
      'shadow-opacity': 0.6,
    },
  },
  // ── Base edge ──
  {
    selector: 'edge',
    style: {
      'width': 1.5,
      'line-color': '#cbd5e1',
      'target-arrow-color': '#94a3b8',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'opacity': 0.8,
    },
  },
  // ── Anomalous edge ──
  {
    selector: 'edge[?is_anomalous]',
    style: {
      'line-color': '#ef4444',
      'target-arrow-color': '#ef4444',
      'line-style': 'dashed',
      'line-dash-pattern': [6, 3],
      'opacity': 0.9,
    },
  },
  // ── Hover ──
  {
    selector: 'node.hovered',
    style: {
      'border-width': 3,
      'border-color': '#8b5cf6',
      'z-index': 9999,
    },
  },
]

/* ── Tooltip component ────────────────────────────────────────────────────── */
function Tooltip({ node, position }) {
  if (!node) return null
  const { label, ip, risk_score, event_count, is_compromised, node_type } = node
  const riskLabel = risk_score > 0.8 ? 'Critical' : risk_score > 0.5 ? 'High' : risk_score > 0.2 ? 'Medium' : 'Low'
  const riskCol   = riskColor(risk_score || 0)

  return (
    <div style={{
      position: 'fixed',
      left: position.x + 14,
      top: position.y - 10,
      zIndex: 9999,
      pointerEvents: 'none',
      background: 'rgba(255,255,255,0.96)',
      backdropFilter: 'blur(12px)',
      border: '1px solid rgba(59,130,246,0.2)',
      borderRadius: 12,
      padding: '12px 16px',
      boxShadow: '0 8px 28px rgba(59,130,246,0.12)',
      minWidth: 200,
      fontFamily: "'Sora', sans-serif",
    }}>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:10 }}>
        <span style={{ fontSize:16 }}>
          {node_type === 'process' ? '⚙️' : node_type === 'user' ? '👤' : '🌐'}
        </span>
        <div>
          <div style={{ fontWeight:800, fontSize:12, color:'#1e3a5f' }}>{label || ip || 'Unknown'}</div>
          <div style={{ fontSize:9, color:'#6b8cae', textTransform:'uppercase', letterSpacing:1 }}>{node_type || 'ip'} node</div>
        </div>
        {is_compromised && (
          <span style={{
            marginLeft:'auto', background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.4)',
            color:'#dc2626', fontSize:8, fontWeight:800, letterSpacing:1,
            padding:'2px 8px', borderRadius:20, textTransform:'uppercase',
          }}>⚠ Compromised</span>
        )}
      </div>

      {/* Stats grid */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'6px 14px' }}>
        {[
          ['IP', ip || label || '—'],
          ['Risk Score', (risk_score || 0).toFixed(3)],
          ['Risk Level', riskLabel],
          ['Events', event_count ?? '—'],
        ].map(([k, v], i) => (
          <div key={i}>
            <div style={{ fontSize:8, color:'#a0bdd4', letterSpacing:1, textTransform:'uppercase', marginBottom:1 }}>{k}</div>
            <div style={{
              fontSize:11, fontWeight:700, fontFamily:'monospace',
              color: k === 'Risk Score' || k === 'Risk Level' ? riskCol : '#1e3a5f',
            }}>{v}</div>
          </div>
        ))}
      </div>

      {/* Risk bar */}
      <div style={{ marginTop:10, height:4, background:'rgba(59,130,246,0.08)', borderRadius:4, overflow:'hidden' }}>
        <div style={{
          height:'100%',
          width: `${Math.min(100, (risk_score || 0) * 100)}%`,
          background: `linear-gradient(90deg, #60a5fa, ${riskCol})`,
          borderRadius:4, transition:'width 0.3s',
        }}/>
      </div>
      <div style={{ display:'flex', justifyContent:'space-between', fontSize:8, color:'#a0bdd4', marginTop:2 }}>
        <span>0%</span><span>Risk</span><span>100%</span>
      </div>
    </div>
  )
}

/* ── Main component ───────────────────────────────────────────────────────── */
export default memo(function AttackGraph() {
  const containerRef = useRef(null)
  const cyRef        = useRef(null)
  const graphData    = useAlertStore(s => s.graphData)

  const [tooltip, setTooltip] = useState(null)          // { node, position: {x,y} }
  const [nodeCount, setNodeCount] = useState(0)
  const [edgeCount, setEdgeCount]  = useState(0)
  const [anomalousCount, setAnomalousCount] = useState(0)

  /* Apply per-node dynamic styles (risk colour, size by event_count) */
  const applyDynamicStyles = useCallback((cy) => {
    cy.nodes().forEach(node => {
      const data  = node.data()
      const color = riskColor(data.risk_score || 0)
      const bdr   = riskBorder(data.risk_score || 0, data.is_compromised)
      // Size ip nodes by event_count (20–50px)
      const base  = data.node_type === 'ip'
        ? Math.min(50, Math.max(20, 20 + (data.event_count || 0) * 0.5))
        : data.node_type === 'process' ? 32 : 28

      node.style({
        'background-color': color + '22',
        'border-color': bdr,
        'border-width': data.is_compromised ? 3.5 : 2,
        'width': base,
        'height': base,
      })
    })

    // Edge thickness by frequency
    cy.edges().forEach(edge => {
      const freq = edge.data('frequency') || 1
      const w = Math.min(5, Math.max(1, freq * 0.5))
      const anomalous = edge.data('is_anomalous')
      edge.style({
        'width': w,
        'line-color': anomalous ? '#ef4444' : '#cbd5e1',
        'target-arrow-color': anomalous ? '#ef4444' : '#94a3b8',
      })
    })
  }, [])

  /* Initialise Cytoscape */
  useEffect(() => {
    if (!containerRef.current) return

    const cy = cytoscape({
      container: containerRef.current,
      style: CY_STYLE,
      layout: { name: 'preset' },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      minZoom: 0.2,
      maxZoom: 4,
    })
    cyRef.current = cy

    /* Node click → tooltip */
    cy.on('tap', 'node', (evt) => {
      const node     = evt.target
      const rendered = node.renderedPosition()
      const container = containerRef.current.getBoundingClientRect()
      setTooltip({
        node: node.data(),
        position: { x: container.left + rendered.x, y: container.top + rendered.y },
      })
      node.select()
    })

    /* Click canvas → close tooltip */
    cy.on('tap', (evt) => {
      if (evt.target === cy) { setTooltip(null); cy.nodes().unselect() }
    })

    /* Hover */
    cy.on('mouseover', 'node', (evt) => evt.target.addClass('hovered'))
    cy.on('mouseout',  'node', (evt) => evt.target.removeClass('hovered'))

    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [])

  /* Update graph when Zustand graphData changes */
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    const nodes = graphData?.nodes || []
    const edges = graphData?.edges || []

    if (!nodes.length && !edges.length) return

    cy.batch(() => {
      /* Add new nodes */
      nodes.forEach(n => {
        if (!cy.getElementById(n.id).length) {
          cy.add({
            group: 'nodes',
            data: {
              id: n.id,
              label: n.label || n.ip || n.id,
              ip: n.ip,
              node_type: n.node_type || 'ip',
              risk_score: n.risk_score || 0,
              event_count: n.event_count || 0,
              is_compromised: n.is_compromised || false,
              role: n.role,
            },
          })
        } else {
          // Update data in place
          cy.getElementById(n.id).data(n)
        }
      })

      /* Add new edges */
      edges.forEach(e => {
        if (!cy.getElementById(e.id).length) {
          cy.add({
            group: 'edges',
            data: {
              id: e.id,
              source: e.source,
              target: e.target,
              is_anomalous: e.is_anomalous || false,
              frequency: e.frequency || 1,
              label: e.label || '',
            },
          })
        }
      })
    })

    applyDynamicStyles(cy)

    /* dagre hierarchical layout — attackers on left, victims on right */
    cy.layout({
      name: 'dagre',
      rankDir: 'LR',              // Left → Right
      nodeSep: 50,
      rankSep: 100,
      edgeSep: 10,
      animate: true,
      animationDuration: 450,
      fit: true,
      padding: 24,
    }).run()

    /* Update counters */
    setNodeCount(cy.nodes().length)
    setEdgeCount(cy.edges().length)
    setAnomalousCount(cy.edges().filter('[?is_anomalous]').length)

  }, [graphData, applyDynamicStyles])

  /* Reference mock data for standalone preview */
  const injectMockData = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    const now = Date.now()
    cy.add([
      { group:'nodes', data:{ id:'att1', label:'192.168.1.10', ip:'192.168.1.10', node_type:'ip', risk_score:0.92, event_count:48, is_compromised:false, role:'attacker' } },
      { group:'nodes', data:{ id:'srv1', label:'10.0.0.5', ip:'10.0.0.5', node_type:'ip', risk_score:0.61, event_count:12, is_compromised:true, role:'server' } },
      { group:'nodes', data:{ id:'p1',   label:'cmd.exe',  node_type:'process', risk_score:0.78, event_count:5 } },
      { group:'nodes', data:{ id:'u1',   label:'admin',    node_type:'user',    risk_score:0.45, event_count:20 } },
      { group:'nodes', data:{ id:'vic1', label:'10.0.0.20', ip:'10.0.0.20', node_type:'ip', risk_score:0.15, event_count:3 } },
      { group:'edges', data:{ id:'e1', source:'att1', target:'srv1', is_anomalous:true,  frequency:9 } },
      { group:'edges', data:{ id:'e2', source:'srv1', target:'p1',   is_anomalous:true,  frequency:4 } },
      { group:'edges', data:{ id:'e3', source:'p1',   target:'u1',   is_anomalous:false, frequency:2 } },
      { group:'edges', data:{ id:'e4', source:'u1',   target:'vic1', is_anomalous:false, frequency:1 } },
    ])
    applyDynamicStyles(cy)
    cy.layout({ name:'dagre', rankDir:'LR', nodeSep:50, rankSep:100, animate:true, animationDuration:400, fit:true, padding:30 }).run()
    setNodeCount(cy.nodes().length)
    setEdgeCount(cy.edges().length)
    setAnomalousCount(cy.edges().filter('[?is_anomalous]').length)
  }, [applyDynamicStyles])

  const fitGraph = () => cyRef.current?.fit(undefined, 24)
  const resetZoom = () => cyRef.current?.zoom({ level: 1, renderedPosition:{ x:300, y:200 } })

  return (
    <div style={{
      background: 'rgba(255,255,255,0.72)',
      backdropFilter: 'blur(18px) saturate(160%)',
      WebkitBackdropFilter: 'blur(18px) saturate(160%)',
      border: '1px solid rgba(96,165,250,0.18)',
      borderRadius: 18,
      boxShadow: '0 4px 24px rgba(59,130,246,0.07)',
      display: 'flex', flexDirection: 'column',
      height: '100%', overflow: 'hidden',
    }}>

      {/* ── Toolbar ─────────────────────────────────────────────────────── */}
      <div style={{
        display:'flex', justifyContent:'space-between', alignItems:'center',
        padding:'12px 18px', borderBottom:'1px solid rgba(96,165,250,0.12)',
      }}>
        {/* Title */}
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <div style={{
            width:32, height:32, borderRadius:10, fontSize:14,
            background:'linear-gradient(135deg, rgba(59,130,246,0.12), rgba(14,165,233,0.06))',
            border:'1px solid rgba(59,130,246,0.15)',
            display:'flex', alignItems:'center', justifyContent:'center',
          }}>🌐</div>
          <div>
            <div style={{ fontWeight:700, fontSize:13, color:'#1e3a5f', fontFamily:"'Sora', sans-serif" }}>Attack Graph</div>
            <div style={{ fontSize:9, color:'#a0bdd4', letterSpacing:1, textTransform:'uppercase' }}>
              Dagre · Hierarchical Layout
            </div>
          </div>
        </div>

        {/* Stats pills */}
        <div style={{ display:'flex', gap:6 }}>
          {[
            [nodeCount, 'nodes', '#3b82f6'],
            [edgeCount, 'edges', '#6b8cae'],
            [anomalousCount, 'anomalous', '#ef4444'],
          ].map(([count, label, color]) => (
            <span key={label} style={{
              background: `${color}11`, border:`1px solid ${color}33`,
              color, borderRadius:20, padding:'3px 10px', fontSize:10, fontFamily:'monospace', fontWeight:700,
            }}>{count} {label}</span>
          ))}
        </div>

        {/* Controls */}
        <div style={{ display:'flex', gap:6 }}>
          {[
            ['Fit', fitGraph, '⊡'],
            ['1x', resetZoom, '◎'],
            ['Mock', injectMockData, '⚡'],
          ].map(([label, fn, icon]) => (
            <button key={label} onClick={fn} style={{
              background:'rgba(59,130,246,0.06)', border:'1px solid rgba(59,130,246,0.18)',
              color:'#3b82f6', borderRadius:8, padding:'5px 12px', fontSize:10,
              fontWeight:600, cursor:'pointer', fontFamily:"'Sora', sans-serif",
              display:'flex', alignItems:'center', gap:4, transition:'all 0.15s',
            }}
              onMouseEnter={e => e.currentTarget.style.background='rgba(59,130,246,0.14)'}
              onMouseLeave={e => e.currentTarget.style.background='rgba(59,130,246,0.06)'}
            >{icon} {label}</button>
          ))}
        </div>
      </div>

      {/* ── Legend ──────────────────────────────────────────────────────── */}
      <div style={{
        display:'flex', gap:16, padding:'8px 18px',
        borderBottom:'1px solid rgba(96,165,250,0.06)',
        flexWrap:'wrap',
      }}>
        <span style={{ fontSize:9, color:'#a0bdd4', fontWeight:700, letterSpacing:1, textTransform:'uppercase', display:'flex', alignItems:'center' }}>
          LEGEND:
        </span>
        {[
          { icon:'○', label:'IP Node', color:'#3b82f6' },
          { icon:'◇', label:'Process', color:'#8b5cf6' },
          { icon:'□', label:'User', color:'#0ea5e9' },
        ].map(({ icon, label, color }) => (
          <span key={label} style={{ display:'flex', alignItems:'center', gap:5, fontSize:10, color:'#6b8cae' }}>
            <span style={{ color, fontWeight:800 }}>{icon}</span>{label}
          </span>
        ))}
        <span style={{ display:'flex', alignItems:'center', gap:5, fontSize:10, color:'#6b8cae' }}>
          <span style={{ width:24, height:2, background:'repeating-linear-gradient(90deg, #ef4444 0, #ef4444 4px, transparent 4px, transparent 8px)', display:'inline-block' }}/>
          Anomalous Edge
        </span>
        {[
          ['#ef4444','Critical >0.8'],
          ['#f97316','High >0.5'],
          ['#eab308','Medium >0.2'],
          ['#3b82f6','Low'],
        ].map(([c,l]) => (
          <span key={l} style={{ display:'flex', alignItems:'center', gap:4, fontSize:9, color:'#6b8cae' }}>
            <span style={{ width:8, height:8, borderRadius:'50%', background:c, display:'inline-block' }}/>
            {l}
          </span>
        ))}
      </div>

      {/* ── Graph canvas ────────────────────────────────────────────────── */}
      <div style={{ flex:1, position:'relative' }}>
        <div ref={containerRef} style={{ width:'100%', height:'100%' }}/>

        {!nodeCount && (
          <div style={{
            position:'absolute', inset:0,
            display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center',
            color:'#c7d9ef', fontSize:12, pointerEvents:'none',
            fontFamily:"'Sora', sans-serif",
          }}>
            <div style={{ fontSize:40, marginBottom:12 }}>🌐</div>
            <div style={{ fontWeight:600, marginBottom:6 }}>No graph data yet</div>
            <div style={{ fontSize:10, color:'#d4e8fc' }}>Start simulation or click ⚡ Mock to preview</div>
          </div>
        )}
      </div>

      {/* ── Tooltip ─────────────────────────────────────────────────────── */}
      {tooltip && <Tooltip node={tooltip.node} position={tooltip.position} />}

      <style>{`
        @keyframes aegis-pulse-node {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.6; }
        }
      `}</style>
    </div>
  )
})
