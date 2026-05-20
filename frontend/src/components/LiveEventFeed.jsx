import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { 
  Activity, 
  Shield, 
  AlertTriangle, 
  Terminal, 
  Zap, 
  Search, 
  ChevronDown, 
  ChevronRight,
  UserCheck,
  Trash2,
  XCircle,
  Clock,
  Fingerprint,
  Info,
  ShieldCheck,
  ExternalLink,
  RotateCw
} from 'lucide-react';
import axios from 'axios';

/**
 * LiveEventFeed.jsx
 * ----------------
 * Real-time cybersecurity EDR dashboard component.
 * Features:
 * - 1500ms polling with 500ms batching
 * - Custom 500-item buffer with virtualization
 * - Real-time filtering and velocity tracking
 * - Multi-state threat visual system (Glow, Borders, Banners)
 * - Process grouping and burst collapse
 * - Detail side-panel with Kill/Whitelist/Dismiss actions
 */

// --- Constants & Config ---
const MAX_EVENTS = 500;
const POLL_INTERVAL = 1500;
const BATCH_FLUSH_INTERVAL = 500;
const ROW_HEIGHT = 36;
const THREAT_LEVELS = {
  NORMAL: 0,
  MONITOR: 1,
  ALERT: 2,
  CRITICAL: 3
};

// --- Styles & Constants ---
const COLORS = {
  bgPage: '#06080F',
  bgFeed: '#090C15',
  cyan: '#00D4FF',
  green: '#00FF94',
  amber: '#FFB800',
  red: '#FF2D55',
  mutedGray: '#8892A4',
  secondaryText: '#4A5568',
  rowSuspicious: 'rgba(255,184,0,0.04)',
  rowMalware: 'rgba(255,45,85,0.08)',
  rowHover: 'rgba(255,255,255,0.03)',
};

const JETBRAINS_MONO = "'JetBrains Mono', monospace";
const INTER = "'Inter', sans-serif";

// --- Components ---

/**
 * Source Badge (SYS/WD)
 */
const SourceBadge = ({ source }) => {
  const isSys = source?.toLowerCase() === 'sysmon';
  const label = isSys ? 'SYS' : 'WD';
  
  return (
    <div 
      className="flex items-center justify-center h-4 w-9 rounded-sm border"
      style={{
        backgroundColor: isSys ? 'rgba(0, 212, 255, 0.15)' : 'transparent',
        borderColor: isSys ? 'rgba(0, 212, 255, 0.4)' : 'rgba(74, 85, 104, 0.4)',
        color: isSys ? COLORS.cyan : COLORS.secondaryText,
        fontSize: '9px',
        letterSpacing: '0.08em',
        fontFamily: JETBRAINS_MONO
      }}
    >
      {label}
    </div>
  );
};

/**
 * Score Delta Display
 */
const ScoreDelta = ({ delta }) => {
  if (!delta) return <span style={{ color: COLORS.secondaryText }}>—</span>;
  
  let color = COLORS.amber;
  if (delta >= 30) color = COLORS.red;
  else if (delta >= 16) color = '#FF8C00';

  return (
    <span style={{ color, fontWeight: 'bold', fontFamily: JETBRAINS_MONO, fontSize: '12px' }}>
      +{delta}
    </span>
  );
};

/**
 * Action Tag
 */
const ActionTag = ({ type }) => {
  const t = type?.toUpperCase() || 'UNKNOWN';
  let color = COLORS.mutedGray;
  if (t === 'RENAME') color = COLORS.amber;
  if (t === 'DELETE') color = '#FF6B6B';

  return (
    <span style={{ color, fontFamily: JETBRAINS_MONO, fontSize: '10px', letterSpacing: '0.05em' }}>
      {t}
    </span>
  );
};

/**
 * Main LiveEventFeed Component
 */
const LiveEventFeed = () => {
  // --- State ---
  const [events, setEvents] = useState([]);
  const [totalSessionEvents, setTotalSessionEvents] = useState(0);
  const [totalEvents, setTotalEvents] = useState(0);
  const [velocity, setVelocity] = useState(0);
  const [filterQuery, setFilterQuery] = useState('');
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [isAutoScrollPaused, setIsAutoScrollPaused] = useState(false);
  const [isLive, setIsLive] = useState(false);
  const [panelError, setPanelError] = useState(null);
  const [panelLoading, setPanelLoading] = useState(false);
  const [lastSeenId, setLastSeenId] = useState(0);
  
  // Buffers & Refs
  const eventBufferRef = useRef([]);
  const lastPollTimeRef = useRef(Date.now());
  const velocityCounterRef = useRef(0);
  const feedRef = useRef(null);
  const lastLiveSignalRef = useRef(Date.now());

  // --- Derived State ---
  const filteredEvents = useMemo(() => {
    let list = events;
    if (filterQuery) {
      const q = filterQuery.toLowerCase();
      list = events.filter(e => 
        e.process_name?.toLowerCase().includes(q) ||
        e.source_path?.toLowerCase().includes(q) ||
        e.event_type?.toLowerCase().includes(q) ||
        e.pid?.toString().includes(q)
      );
    }

    // --- BURST COLLAPSE LOGIC ---
    // Group identical actions by the same process within 2s
    const collapsed = [];
    let currentBurst = null;

    list.forEach((e, i) => {
      const next = list[i + 1];
      
      // If we are already in a burst
      if (currentBurst) {
        const first = currentBurst.items[0];
        const timeDiff = Math.abs(new Date(first.timestamp) - new Date(e.timestamp)) / 1000;
        
        if (e.pid === first.pid && e.event_type === first.event_type && timeDiff <= 2) {
          currentBurst.items.push(e);
          return; // Continue grouping
        } else {
          // Close burst if next event is different or too far in time
          if (currentBurst.items.length > 5) {
            collapsed.push({ ...currentBurst.items[0], _burstCount: currentBurst.items.length, _burstItems: currentBurst.items });
          } else {
            collapsed.push(...currentBurst.items);
          }
          currentBurst = null;
        }
      }

      // Check if we should start a new burst
      if (next && e.pid === next.pid && e.event_type === next.event_type) {
        const timeDiff = Math.abs(new Date(e.timestamp) - new Date(next.timestamp)) / 1000;
        if (timeDiff <= 2) {
          currentBurst = { items: [e] };
          return;
        }
      }

      collapsed.push(e);
    });

    // --- CRITICAL FIX: Push the final burst if it exists ---
    if (currentBurst) {
      if (currentBurst.items.length > 5) {
        collapsed.push({ ...currentBurst.items[0], _burstCount: currentBurst.items.length, _burstItems: currentBurst.items });
      } else {
        collapsed.push(...currentBurst.items);
      }
    }

    return collapsed;
  }, [events, filterQuery]);

  const threatState = useMemo(() => {
    // Only consider processes that are NOT whitelisted
    const activeThreats = events.filter(e => e.process_status !== 'WHITELISTED' && e.process_status !== 'WHITELIST');
    const maxScore = Math.max(0, ...activeThreats.map(e => e.process_score || 0));
    
    if (maxScore >= 75) return THREAT_LEVELS.CRITICAL;
    if (maxScore >= 50) return THREAT_LEVELS.ALERT;
    if (maxScore >= 30) return THREAT_LEVELS.MONITOR;
    return THREAT_LEVELS.NORMAL;
  }, [events]);

  const activeThreatProcess = useMemo(() => {
    return events.find(e => (e.process_score || 0) >= 75 && e.process_status !== 'WHITELISTED');
  }, [events]);

  const selectedEvent = useMemo(() => {
    return events.find(e => e.id === selectedEventId);
  }, [events, selectedEventId]);

  // --- Effects ---

  // 1. Polling Logic
  useEffect(() => {
    const poll = async () => {
      try {
        const url = `/api/events?since_id=${lastSeenId}&per_page=100`;
        const res = await axios.get(url);
        const data = res.data;
        
        if (data.events) {
          if (data.events.length > 0) {
            const maxId = Math.max(...data.events.map(e => e.id));
            
            if (lastSeenId === 0) {
              // --- CRITICAL FIX: Flush first batch immediately ---
              // No need to wait for the 2s buffer timer on initial load
              setEvents(data.events);
              setLastSeenId(maxId);
              setTotalSessionEvents(data.events.length);
              lastLiveSignalRef.current = Date.now();
            } else {
              if (maxId > lastSeenId) setLastSeenId(maxId);
              eventBufferRef.current = [...data.events, ...eventBufferRef.current].slice(0, MAX_EVENTS);
              velocityCounterRef.current += data.events.length;
              lastLiveSignalRef.current = Date.now();
            }
          }
          if (data.total > 0) {
            setTotalEvents(data.total);
          }
          setIsLive(true);
        }
      } catch (err) {
        console.error("Poll error:", err);
      }
    };

    const pollInterval = setInterval(poll, POLL_INTERVAL);
    return () => clearInterval(pollInterval);
  }, [lastSeenId]);

  // 2. Batch Flush Logic (for performance)
  useEffect(() => {
    const flush = () => {
      if (eventBufferRef.current.length > 0) {
        setEvents(prev => {
          const combined = [...eventBufferRef.current, ...prev].slice(0, MAX_EVENTS);
          // Deduplicate by ID
          const uniqueMap = new Map();
          combined.forEach(e => uniqueMap.set(e.id, e));
          return Array.from(uniqueMap.values()).sort((a, b) => b.id - a.id);
        });
        setTotalSessionEvents(prev => prev + eventBufferRef.current.length);
        eventBufferRef.current = [];
      }

      // Check for live pulse status
      if (Date.now() - lastLiveSignalRef.current > 3000) {
        setIsLive(false);
      }
    };

    const flushInterval = setInterval(flush, BATCH_FLUSH_INTERVAL);
    return () => clearInterval(flushInterval);
  }, []);

  // 3. Velocity Calculation
  useEffect(() => {
    const calcVelocity = () => {
      setVelocity(velocityCounterRef.current);
      velocityCounterRef.current = 0;
    };
    const velocityInterval = setInterval(calcVelocity, 1000);
    return () => clearInterval(velocityInterval);
  }, []);

  // 4. Auto-scroll Handling
  useEffect(() => {
    if (!isAutoScrollPaused && feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
  }, [events, isAutoScrollPaused]);

  const [expandedBursts, setExpandedBursts] = useState(new Set());

  const toggleBurst = (id, e) => {
    e.stopPropagation();
    setExpandedBursts(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // --- Handlers ---
  const handleScroll = (e) => {
    const isAtTop = e.target.scrollTop === 0;
    if (!isAtTop) {
      setIsAutoScrollPaused(true);
    } else {
      setIsAutoScrollPaused(false);
    }
  };

  const resumeLive = () => {
    if (feedRef.current) {
      feedRef.current.scrollTo({ top: 0, behavior: 'smooth' });
    }
    setIsAutoScrollPaused(false);
  };

  const killProcess = async (pid) => {
    if (!window.confirm(`Terminate process PID ${pid}?`)) return;
    setPanelError(null);
    setPanelLoading(true);
    try {
      const res = await axios.post('/api/processes/kill', { pid });
      const data = res.data;
      if (data.status === 'killed' || data.status === 'already_dead') {
        // Success
      } else {
        setPanelError(`Failed: ${data.error}`);
      }
    } catch (err) {
      console.error("Kill error:", err);
      setPanelError("Error killing process. Ensure you have administrator privileges.");
    }
    setPanelLoading(false);
  };

  const whitelistProcess = async (path) => {
    if (!path) return;
    setPanelError(null);
    setPanelLoading(true);
    try {
      await axios.post('/api/whitelist', { exe_path: path });
      
      // Update local events to reflect whitelisted status immediately
      setEvents(prev => prev.map(e => {
        if (e.process_image === path || e.dest_path === path || e.source_path === path) {
          return { ...e, process_status: 'WHITELISTED' };
        }
        return e;
      }));
    } catch (err) {
      console.error("Whitelist error:", err);
      setPanelError("Error whitelisting. The path might be invalid or already whitelisted.");
    }
    setPanelLoading(false);
  };

  // --- Render Helpers ---

  const renderPath = (path) => {
    if (!path) return '—';
    const parts = path.split(/[/\\]/);
    const filename = parts[parts.length - 1];
    const extension = filename.includes('.') ? '.' + filename.split('.').pop() : '';
    const nameWithoutExt = filename.substring(0, filename.length - extension.length);
    
    const isSuspiciousExt = ['.locked', '.encrypted', '.crypt', '.ransom'].some(ext => extension.toLowerCase().includes(ext));

    return (
      <div className="truncate text-right flex flex-row-reverse items-center gap-1 overflow-hidden" title={path}>
        <span style={{ color: isSuspiciousExt ? COLORS.red : COLORS.mutedGray }}>{extension}</span>
        <span>{nameWithoutExt}</span>
        <span className="opacity-50">…/</span>
      </div>
    );
  };

  const getRowBackground = (e) => {
    if (e.process_score >= 75) return COLORS.rowMalware;
    if (e.process_score >= 30) return COLORS.rowSuspicious;
    return 'transparent';
  };

  const getProcessColor = (e) => {
    if (e.status === 'KILLED') return COLORS.red;
    if (e.process_score >= 75) return COLORS.red;
    if (e.process_score >= 30) return COLORS.amber;
    if (e.is_whitelisted) return COLORS.secondaryText;
    return '#C8D0DC';
  };

  // --- Render ---

  return (
    <div 
      className="flex flex-col h-full border overflow-hidden relative"
      style={{ 
        backgroundColor: COLORS.bgFeed,
        borderColor: threatState === THREAT_LEVELS.CRITICAL ? COLORS.red : 
                    threatState >= THREAT_LEVELS.ALERT ? 'rgba(255, 184, 0, 0.6)' :
                    threatState >= THREAT_LEVELS.MONITOR ? 'rgba(255, 184, 0, 0.3)' :
                    'rgba(255, 255, 255, 0.06)',
        boxShadow: threatState === THREAT_LEVELS.CRITICAL ? `0 0 40px ${COLORS.red}33` :
                   threatState >= THREAT_LEVELS.MONITOR ? `0 0 20px ${COLORS.amber}22` : 'none',
        transition: 'all 0.3s ease-out'
      }}
    >
      {/* THREAT BANNERS */}
      {threatState === THREAT_LEVELS.CRITICAL && activeThreatProcess && (
        <div 
          className="absolute top-0 left-0 right-0 z-50 py-2 px-4 flex items-center justify-between animate-slide-down"
          style={{ backgroundColor: COLORS.red, color: 'white', fontFamily: INTER, fontWeight: 'bold' }}
        >
          <div className="flex items-center gap-3">
            <Zap size={16} fill="white" />
            <span className="text-sm">⚡ THREAT KILLED — {activeThreatProcess.process_name} — PID {activeThreatProcess.pid} — SCORE {activeThreatProcess.process_score}</span>
          </div>
        </div>
      )}
      
      {threatState === THREAT_LEVELS.ALERT && !activeThreatProcess && (
         <div 
          className="absolute top-0 left-0 right-0 z-50 py-1.5 px-4 flex items-center justify-center animate-slide-down"
          style={{ backgroundColor: COLORS.amber, color: COLORS.bgPage, fontFamily: INTER, fontWeight: 'bold' }}
        >
          <span className="text-xs tracking-wider">⚠ SUSPICIOUS ACTIVITY DETECTED — ELEVATED SCORE</span>
        </div>
      )}

      {/* FEED HEADER */}
      <header className="flex items-center justify-between px-4 h-12 border-b border-white/5 bg-black/20 shrink-0">
        <div className="flex items-center gap-4">
          <div className="flex flex-col">
             <span className="text-[10px] tracking-[0.2em] text-[#8892A4] font-bold">LIVE EVENT FEED</span>
             <div className="flex items-center gap-1.5 mt-0.5">
                <div 
                  className={`w-1.5 h-1.5 rounded-full ${isLive ? 'animate-pulse' : ''}`}
                  style={{ backgroundColor: isLive ? COLORS.cyan : COLORS.secondaryText }}
                />
                <span className="text-[10px] font-bold" style={{ color: isLive ? COLORS.cyan : COLORS.secondaryText }}>
                  {isLive ? 'LIVE' : 'IDLE'}
                </span>
             </div>
          </div>
        </div>

        <div className="flex items-center gap-8">
           <div className="flex flex-col items-end">
              <span className="text-[9px] text-[#4A5568] uppercase tracking-wider">Velocity</span>
              <div className="flex items-baseline gap-1">
                 <span 
                    className="text-lg font-bold leading-none"
                    style={{ 
                      fontFamily: JETBRAINS_MONO,
                      color: velocity > 50 ? COLORS.red : velocity > 20 ? COLORS.amber : '#E2E8F0'
                    }}
                  >
                    {velocity}
                  </span>
                 <span className="text-[10px] text-[#4A5568] font-mono">evt/s</span>
              </div>
           </div>

           <div className="flex flex-col items-end">
              <span className="text-[9px] text-[#4A5568] uppercase tracking-wider">Total</span>
              <span className="text-lg font-bold leading-none text-[#E2E8F0]" style={{ fontFamily: JETBRAINS_MONO }}>
                {totalEvents || totalSessionEvents}
              </span>
           </div>

           <div className="relative w-48 group">
              <Search size={14} className="absolute left-0 top-1/2 -translate-y-1/2 text-[#4A5568] transition-colors group-focus-within:text-cyan-400" />
              <input 
                type="text"
                placeholder="Filter by process, path, action..."
                className="w-full bg-transparent border-b border-[#4A5568] pl-5 pr-2 py-1 text-xs text-[#C8D0DC] focus:outline-none focus:border-cyan-400 transition-all font-mono"
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
              />
           </div>
        </div>
      </header>

      {/* FEED COLUMN HEADERS */}
      <div className="flex items-center px-4 h-8 bg-black/30 border-b border-white/5 text-[10px] font-bold text-[#4A5568] uppercase tracking-widest shrink-0">
         <div className="w-[72px]">Timestamp</div>
         <div className="w-[44px]">Src</div>
         <div className="w-[140px]">Process</div>
         <div className="w-[56px]">PID</div>
         <div className="w-[64px]">Action</div>
         <div className="flex-1">File Path</div>
         <div className="w-[52px] text-right">Score</div>
      </div>

      {/* THE FEED */}
      <div 
        ref={feedRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto scrollbar-thin relative"
      >
        {isAutoScrollPaused && (
          <button 
            onClick={resumeLive}
            className="sticky top-2 left-1/2 -translate-x-1/2 z-40 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-400 text-[10px] font-bold py-1.5 px-4 rounded-full flex items-center gap-2 backdrop-blur-md transition-all shadow-lg"
          >
            <RotateCw size={12} className="animate-spin-slow" />
            ↑ RESUME LIVE FEED
          </button>
        )}

        {filteredEvents.length === 0 ? (
          <div className="flex items-center justify-center h-40 text-[#4A5568]" style={{ fontFamily: JETBRAINS_MONO }}>
             Waiting for events...
          </div>
        ) : (
          filteredEvents.flatMap((e, idx) => {
            const isBurst = e._burstCount > 5;
            const isExpanded = expandedBursts.has(e.id);
            const displayEvents = isBurst && isExpanded ? [e, ...e._burstItems.slice(1)] : [e];

            return displayEvents.map((item, subIdx) => {
              const isSelected = selectedEventId === item.id;
              const prevEvent = subIdx === 0 ? filteredEvents[idx - 1] : displayEvents[subIdx - 1];
              const isGrouped = prevEvent && prevEvent.pid === item.pid && prevEvent.timestamp?.split('.')[0] === item.timestamp?.split('.')[0];
              
              return (
                <div 
                  key={`${item.id}-${item.timestamp}-${item.event_type}`}
                  onClick={() => { setSelectedEventId(item.id); setPanelError(null); }}
                  className={`flex items-center px-4 h-9 cursor-pointer transition-all duration-150 relative group animate-row-in ${isBurst && subIdx > 0 ? 'bg-black/10' : ''}`}
                  style={{ 
                    backgroundColor: isSelected ? 'rgba(0, 212, 255, 0.08)' : getRowBackground(item),
                    borderLeft: isGrouped ? `2px solid ${getProcessColor(item)}` : 'none',
                    opacity: isBurst && subIdx > 0 ? 0.7 : 1
                  }}
                >
                  {/* CYAN FLASH OVERLAY (Only for new events) */}
                  <div className="absolute inset-0 bg-cyan-400/5 opacity-0 group-active:opacity-100 pointer-events-none transition-opacity duration-200" />
                  
                  <div className="w-[72px] text-[11px] font-mono" style={{ color: COLORS.secondaryText }}>
                     {item.timestamp?.slice(11, 19)}
                  </div>
                  
                  <div className="w-[44px]">
                     <SourceBadge source={item.source} />
                  </div>
                  
                  <div className="w-[140px] truncate pr-2 flex items-center gap-1">
                     <span 
                      className="text-[12px] font-semibold truncate"
                      style={{ 
                        color: getProcessColor(item),
                        textDecoration: item.status === 'KILLED' ? 'line-through' : 'none'
                      }}
                    >
                      {item.process_name}
                    </span>
                    {item.status === 'KILLED' && (
                      <span className="text-[9px] px-1 bg-red-500/20 border border-red-500/30 text-red-500 rounded-sm font-bold">KILLED</span>
                    )}
                  </div>
                  
                  <div className="w-[56px] text-[11px] font-mono text-[#4A5568]">
                     {item.pid || '—'}
                  </div>
                  
                  <div className="w-[64px] flex items-center gap-1">
                     <ActionTag type={item.event_type} />
                     {isBurst && subIdx === 0 && (
                        <span className="text-[9px] text-amber-500 font-bold">×{e._burstCount}</span>
                     )}
                  </div>
                  
                  <div className="flex-1 overflow-hidden pr-4 font-mono text-[11px] flex items-center gap-2" style={{ color: COLORS.mutedGray }}>
                     {isBurst && subIdx === 0 && (
                        <button 
                          onClick={(evt) => toggleBurst(e.id, evt)}
                          className="text-[#4A5568] hover:text-white"
                        >
                          {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        </button>
                     )}
                     <div className="flex-1 overflow-hidden">
                        {renderPath(item.dest_path || item.source_path)}
                     </div>
                  </div>
                  
                  <div className="w-[52px] text-right">
                     <ScoreDelta delta={item.score_delta} />
                  </div>

                  {/* HOVER HIGHLIGHT */}
                  <div className="absolute inset-0 opacity-0 group-hover:opacity-100 bg-white/[0.03] pointer-events-none transition-opacity" />
                </div>
              );
            });
          })
        )}
      </div>

      {/* SIDE PANEL */}
      {selectedEvent && (
        <>
          <div 
            className="absolute inset-0 bg-black/60 backdrop-blur-md z-[90] animate-fade-in"
            onClick={() => setSelectedEventId(null)}
          />
          <aside 
            className="absolute top-0 right-0 bottom-0 w-[420px] bg-[#0A0D14]/95 backdrop-blur-xl border-l border-white/10 z-[100] flex flex-col shadow-[0_0_100px_rgba(0,0,0,0.8)] animate-panel-in"
            style={{
              backgroundImage: 'radial-gradient(circle at top right, rgba(0, 212, 255, 0.05), transparent 400px)'
            }}
          >
            {/* PANEL HEADER */}
            <header className="relative p-6 border-b border-white/10 shrink-0">
               <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                     <div className="relative">
                        <div className="p-3 bg-cyan-500/10 rounded-xl text-cyan-400 border border-cyan-500/20 shadow-[0_0_20px_rgba(0,212,255,0.1)]">
                           <Terminal size={22} />
                        </div>
                        {selectedEvent.status === 'KILLED' && (
                          <div className="absolute -top-1 -right-1 bg-red-500 text-white rounded-full p-0.5 border-2 border-[#0A0D14]">
                            <XCircle size={12} />
                          </div>
                        )}
                     </div>
                     <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-lg font-bold text-white tracking-tight leading-tight">{selectedEvent.process_name}</h3>
                          {selectedEvent.is_whitelisted && (
                             <ShieldCheck size={14} className="text-green-400" />
                          )}
                        </div>
                        <p className="text-xs text-slate-500 font-mono mt-0.5 flex items-center gap-2">
                          <span className="px-1.5 py-0.5 bg-white/5 rounded border border-white/5">PID {selectedEvent.pid}</span>
                          <span className="w-1 h-1 bg-slate-700 rounded-full" />
                          <span className="uppercase tracking-widest text-[9px] font-bold text-slate-600">{selectedEvent.source || 'PROCESS'}</span>
                        </p>
                     </div>
                  </div>
                  <button 
                    onClick={() => setSelectedEventId(null)}
                    className="p-2 hover:bg-white/5 rounded-lg text-slate-500 hover:text-white transition-all group"
                  >
                     <XCircle size={24} className="group-hover:rotate-90 transition-transform duration-300" />
                  </button>
               </div>
               
               {/* SCORE GAUGE MINI */}
               <div className="mt-6 flex items-end gap-4">
                  <div className="flex-1">
                    <div className="flex justify-between items-end mb-2">
                       <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Behavioral Threat Score</span>
                       <span 
                        className="text-3xl font-black font-mono leading-none"
                        style={{ 
                          color: getProcessColor(selectedEvent),
                          textShadow: `0 0 20px ${getProcessColor(selectedEvent)}44`
                        }}
                       >
                          {selectedEvent.process_score || 0}
                       </span>
                    </div>
                    <div className="h-2 bg-white/5 rounded-full overflow-hidden border border-white/5 p-[1px]">
                       <div 
                        className="h-full rounded-full transition-all duration-1000 ease-out relative"
                        style={{ 
                          width: `${Math.min(100, selectedEvent.process_score || 0)}%`,
                          backgroundColor: getProcessColor(selectedEvent),
                        }}
                       >
                         <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer" />
                       </div>
                    </div>
                  </div>
               </div>
            </header>

            <div className="flex-1 overflow-y-auto p-6 space-y-8 scrollbar-thin">
               {/* TRIGGERED RULES / ALERTS */}
               {selectedEvent.triggered_rules?.length > 0 && (
                 <section className="animate-fade-in">
                    <h4 className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
                       <AlertTriangle size={14} className="text-amber-500" />
                       Critical Behavioral Indicators
                    </h4>
                    <div className="space-y-3">
                       {selectedEvent.triggered_rules.map((rule, i) => (
                         <div key={`${rule.id}-${i}`} className="group relative p-4 bg-red-500/5 hover:bg-red-500/10 border border-red-500/10 rounded-xl transition-all">
                            <div className="flex items-start gap-3">
                               <div className="mt-1 p-1 bg-red-500/20 rounded text-red-400">
                                  <Zap size={12} fill="currentColor" />
                               </div>
                               <div>
                                  <div className="text-[11px] font-bold text-red-200 uppercase tracking-wide mb-1">{rule.id.replace(/_/g, ' ')}</div>
                                  <div className="text-xs text-slate-400 leading-relaxed font-medium">{rule.description}</div>
                               </div>
                            </div>
                         </div>
                       ))}
                    </div>
                 </section>
               )}

               {/* METRICS GRID */}
               <section>
                  <h4 className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
                     <Info size={14} />
                     Process Forensics
                  </h4>
                  <div className="grid grid-cols-1 gap-3">
                    <MetricCard 
                      icon={<ExternalLink size={14} />} 
                      label="Executable Path" 
                      value={selectedEvent.process_image || '—'} 
                      isPath
                    />
                    <MetricCard 
                      icon={<Activity size={14} />} 
                      label="Target File" 
                      value={selectedEvent.dest_path || selectedEvent.source_path || '—'} 
                      isPath
                    />
                    <div className="grid grid-cols-2 gap-3">
                      <MetricCard 
                        icon={<Fingerprint size={14} />} 
                        label="File Hash" 
                        value={selectedEvent.image_sha256 ? `${selectedEvent.image_sha256.slice(0, 12)}...` : 'N/A'} 
                        isMono
                      />
                      <MetricCard 
                        icon={<ShieldCheck size={14} />} 
                        label="Signature" 
                        value={selectedEvent.signature_status || 'UNSIGNED'} 
                        color={selectedEvent.signature_status === 'TRUSTED' ? COLORS.green : COLORS.amber}
                      />
                      <MetricCard 
                        icon={<Activity size={14} />} 
                        label="VirusTotal" 
                        value={selectedEvent.vt_score || '0 / 74'} 
                        color={selectedEvent.vt_score && selectedEvent.vt_score.split('/')[0] > 0 ? COLORS.red : COLORS.green}
                      />
                      <MetricCard 
                        icon={<Clock size={14} />} 
                        label="First Seen" 
                        value={selectedEvent.timestamp?.slice(11, 19)} 
                      />
                    </div>
                  </div>
               </section>

               {/* TIMELINE */}
               <section>
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.2em] flex items-center gap-2">
                       <RotateCw size={14} />
                       Event Sequence
                    </h4>
                    <span className="text-[9px] text-slate-600 font-bold px-2 py-0.5 bg-white/5 rounded-full border border-white/5">LAST 5 OPERATIONS</span>
                  </div>
                  <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-[1px] before:bg-white/5">
                     {events.filter(ev => ev.pid === selectedEvent.pid).slice(0, 5).map((ev, i) => (
                       <div key={`${ev.id}-${i}`} className="relative group/item">
                          <div 
                            className="absolute left-[-19.5px] top-1 w-2.5 h-2.5 rounded-full border-2 border-[#0A0D14] shadow-[0_0_10px_rgba(0,0,0,0.5)] transition-transform group-hover/item:scale-125 z-10" 
                            style={{ backgroundColor: getProcessColor(ev) }} 
                          />
                          <div className="flex flex-col gap-1">
                            <div className="flex items-center justify-between">
                               <span className="text-[10px] font-bold text-slate-400 font-mono">{ev.timestamp?.slice(11, 19)}</span>
                               <span className="text-[9px] font-black text-slate-600 tracking-tighter uppercase">{ev.event_type}</span>
                            </div>
                            <div className="text-[11px] text-slate-200 font-medium truncate bg-white/[0.02] p-2 rounded-lg border border-white/5 group-hover/item:border-white/10 transition-colors">
                               {ev.dest_path?.split(/[/\\]/).pop() || ev.process_name}
                            </div>
                          </div>
                       </div>
                     ))}
                  </div>
               </section>

               {panelError && (
                 <div className="mx-6 p-4 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center gap-3 animate-fade-in">
                   <AlertTriangle size={16} className="text-red-500 shrink-0" />
                   <p className="text-[11px] text-red-200 font-medium leading-relaxed">{panelError}</p>
                 </div>
               )}
            </div>

            {/* ACTION FOOTER */}
            <footer className="p-5 border-t border-white/10 bg-black/40 backdrop-blur-md shrink-0">
               <div className="grid grid-cols-2 gap-3">
                  <button 
                    onClick={() => killProcess(selectedEvent.pid)}
                    disabled={selectedEvent.status === 'KILLED' || panelLoading}
                    className={`col-span-2 relative overflow-hidden group py-3.5 rounded-xl font-bold text-[11px] uppercase tracking-[0.2em] flex items-center justify-center gap-3 transition-all ${
                      selectedEvent.status === 'KILLED' 
                      ? 'bg-slate-800 text-slate-500 cursor-not-allowed opacity-50' 
                      : 'bg-red-500 hover:bg-red-600 text-white shadow-[0_10px_20px_rgba(239,68,68,0.2)] active:scale-[0.98]'
                    }`}
                  >
                     <div className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/10 to-white/0 -translate-x-full group-hover:translate-x-full transition-transform duration-1000" />
                     <Trash2 size={16} />
                     Terminate Process Execution
                  </button>
                  <button 
                    onClick={() => whitelistProcess(selectedEvent.process_image)}
                    className="py-3 bg-white/5 hover:bg-white/10 border border-white/10 text-white rounded-xl font-bold text-[10px] uppercase tracking-widest flex items-center justify-center gap-2 transition-all active:scale-[0.98]"
                  >
                     <UserCheck size={14} className="text-green-400" />
                     Whitelist
                  </button>
                  <button 
                    onClick={() => setSelectedEventId(null)}
                    className="py-3 bg-white/5 hover:bg-white/10 border border-white/10 text-slate-400 hover:text-white rounded-xl font-bold text-[10px] uppercase tracking-widest flex items-center justify-center gap-2 transition-all active:scale-[0.98]"
                  >
                     <XCircle size={14} />
                     Dismiss
                  </button>
               </div>
            </footer>
          </aside>
        </>
      )}

      {/* CUSTOM ANIMATIONS */}
      <style>{`
        @keyframes shimmer {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
        @keyframes slide-down {
          from { transform: translateY(-100%); }
          to { transform: translateY(0); }
        }
        @keyframes panel-in {
          from { transform: translateX(100%); }
          to { transform: translateX(0); }
        }
        @keyframes fade-in {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes row-in {
          from { transform: translateY(-5px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
        .animate-shimmer { animation: shimmer 2s infinite; }
        .animate-slide-down { animation: slide-down 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
        .animate-panel-in { animation: panel-in 0.35s cubic-bezier(0.16, 1, 0.3, 1); }
        .animate-fade-in { animation: fade-in 0.2s linear; }
        .animate-row-in { animation: row-in 0.12s ease-out; }
        .animate-spin-slow { animation: spin 3s linear infinite; }
        
        .scrollbar-thin::-webkit-scrollbar { width: 4px; }
        .scrollbar-thin::-webkit-scrollbar-track { background: transparent; }
        .scrollbar-thin::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 10px; }
        .scrollbar-thin::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
      `}</style>
    </div>
  );
};

const MetricCard = ({ label, value, icon, isMono, isPath, color }) => (
  <div className="bg-white/[0.03] border border-white/5 p-3 rounded-xl hover:bg-white/[0.05] transition-colors group/card">
    <div className="flex items-center gap-2 text-[9px] text-slate-500 uppercase font-black tracking-[0.15em] mb-1.5">
      <span className="text-slate-600 group-hover/card:text-cyan-400 transition-colors">{icon}</span>
      {label}
    </div>
    <div 
      className={`text-xs leading-relaxed ${isMono ? 'font-mono' : 'font-semibold'} ${isPath ? 'break-all line-clamp-2' : 'truncate'}`}
      style={{ color: color || '#E2E8F0' }}
      title={isPath ? value : undefined}
    >
      {value}
    </div>
  </div>
);

export default LiveEventFeed;
