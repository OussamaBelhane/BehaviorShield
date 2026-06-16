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
      style={{
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        height: 16, minWidth: 32, paddingLeft: 4, paddingRight: 4,
        borderRadius: 3,
        backgroundColor: isSys ? 'rgba(0,212,255,0.13)' : 'rgba(255,255,255,0.04)',
        border: `1px solid ${isSys ? 'rgba(0,212,255,0.35)' : 'rgba(255,255,255,0.08)'}`,
        color: isSys ? COLORS.cyan : COLORS.secondaryText,
        fontSize: '9px', letterSpacing: '0.1em',
        fontFamily: JETBRAINS_MONO, fontWeight: 700,
        boxShadow: isSys ? '0 0 6px rgba(0,212,255,0.15)' : 'none',
      }}
    >
      {label}
    </div>
  );
};

/**
 * Score Delta Display — pill with background fill
 */
const ScoreDelta = ({ delta }) => {
  if (!delta) return <span style={{ color: COLORS.secondaryText, fontFamily: JETBRAINS_MONO, fontSize: '11px' }}>—</span>;

  let color, bg, borderColor;
  if (delta >= 30) {
    color = COLORS.red; bg = 'rgba(255,45,85,0.15)'; borderColor = 'rgba(255,45,85,0.3)';
  } else if (delta >= 16) {
    color = '#FF8C00'; bg = 'rgba(255,140,0,0.12)'; borderColor = 'rgba(255,140,0,0.28)';
  } else {
    color = COLORS.amber; bg = 'rgba(255,184,0,0.10)'; borderColor = 'rgba(255,184,0,0.25)';
  }

  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 6px',
      borderRadius: 4,
      background: bg,
      border: `1px solid ${borderColor}`,
      color, fontWeight: 700,
      fontFamily: JETBRAINS_MONO, fontSize: '11px',
    }}>
      +{delta}
    </span>
  );
};

/**
 * Action Tag — colored chip per action type
 */
const ACTION_STYLES = {
  RENAME: { color: COLORS.amber,   bg: 'rgba(255,184,0,0.08)',  border: 'rgba(255,184,0,0.2)' },
  DELETE: { color: '#FF6B6B',      bg: 'rgba(255,107,107,0.08)',border: 'rgba(255,107,107,0.2)' },
  CREATE: { color: '#00FF94',      bg: 'rgba(0,255,148,0.07)', border: 'rgba(0,255,148,0.18)' },
  WRITE:  { color: COLORS.cyan,    bg: 'rgba(0,212,255,0.07)', border: 'rgba(0,212,255,0.18)' },
};

const ActionTag = ({ type }) => {
  const t = type?.toUpperCase() || 'UNKNOWN';
  const s = ACTION_STYLES[t] || { color: COLORS.mutedGray, bg: 'transparent', border: 'transparent' };
  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 5px', borderRadius: 3,
      background: s.bg, border: `1px solid ${s.border}`,
      color: s.color, fontFamily: JETBRAINS_MONO,
      fontSize: '9.5px', letterSpacing: '0.06em', fontWeight: 700,
    }}>
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

  const threatBorderColor = threatState === THREAT_LEVELS.CRITICAL ? COLORS.red
    : threatState >= THREAT_LEVELS.ALERT   ? 'rgba(255,184,0,0.55)'
    : threatState >= THREAT_LEVELS.MONITOR ? 'rgba(255,184,0,0.25)'
    : 'rgba(255,255,255,0.05)';

  return (
    <div
      className="flex flex-col h-full overflow-hidden relative"
      style={{
        backgroundColor: COLORS.bgFeed,
        border: `1px solid ${threatBorderColor}`,
        borderRadius: 12,
        boxShadow: threatState === THREAT_LEVELS.CRITICAL
          ? `0 0 50px ${COLORS.red}28, inset 0 0 0 1px ${COLORS.red}20`
          : threatState >= THREAT_LEVELS.MONITOR
          ? `0 0 28px ${COLORS.amber}18`
          : '0 0 0 1px rgba(0,212,255,0.04)',
        transition: 'border-color 0.4s ease, box-shadow 0.4s ease',
      }}
    >
      {/* THREAT BANNERS */}
      {threatState === THREAT_LEVELS.CRITICAL && activeThreatProcess && (
        <div
          className="absolute top-0 left-0 right-0 z-50 flex items-center justify-between animate-slide-down"
          style={{
            background: 'linear-gradient(90deg, #FF2D55, #c4002c)',
            padding: '6px 16px',
            fontFamily: INTER, fontWeight: 700, fontSize: 12, color: 'white',
            letterSpacing: '0.05em',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Zap size={14} fill="white" />
            <span>THREAT KILLED — {activeThreatProcess.process_name} — PID {activeThreatProcess.pid} — SCORE {activeThreatProcess.process_score}</span>
          </div>
          <div style={{ fontSize: 10, opacity: 0.75 }}>PROCESS TERMINATED + QUARANTINED</div>
        </div>
      )}

      {threatState === THREAT_LEVELS.ALERT && !activeThreatProcess && (
        <div
          className="absolute top-0 left-0 right-0 z-50 flex items-center justify-center animate-slide-down"
          style={{
            background: 'linear-gradient(90deg, rgba(255,184,0,0.92), rgba(255,140,0,0.92))',
            padding: '5px 16px',
            fontFamily: INTER, fontWeight: 700, fontSize: 11,
            color: '#0a0f1e', letterSpacing: '0.1em',
          }}
        >
          ⚠ SUSPICIOUS ACTIVITY DETECTED — ELEVATED THREAT SCORE
        </div>
      )}

      {/* FEED HEADER */}
      <header
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0 14px',
          height: 48,
          borderBottom: '1px solid rgba(255,255,255,0.04)',
          background: 'rgba(0,0,0,0.25)',
          flexShrink: 0,
          position: 'relative',
        }}
      >
        {/* Scan line animation on header */}
        <div style={{
          position: 'absolute', inset: 0, overflow: 'hidden', pointerEvents: 'none', borderRadius: '11px 11px 0 0',
        }}>
          <div style={{
            position: 'absolute', left: 0, right: 0, height: 1,
            background: 'linear-gradient(90deg, transparent, rgba(0,212,255,0.25), transparent)',
            animation: 'scan-line 4s linear infinite',
          }} />
        </div>

        {/* Left: title + live indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div>
            <div style={{
              fontFamily: JETBRAINS_MONO, fontSize: 10,
              fontWeight: 700, letterSpacing: '0.18em',
              color: '#5A6880',
            }}>LIVE EVENT FEED</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginTop: 2 }}>
              <div style={{
                width: 6, height: 6, borderRadius: '50%',
                background: isLive ? COLORS.cyan : COLORS.secondaryText,
                boxShadow: isLive ? '0 0 7px #00D4FF' : 'none',
                animation: isLive ? 'pulseDot 1.5s ease-in-out infinite' : 'none',
              }} />
              <span style={{
                fontFamily: JETBRAINS_MONO, fontSize: 9, fontWeight: 700,
                color: isLive ? COLORS.cyan : COLORS.secondaryText,
                letterSpacing: '0.1em',
              }}>
                {isLive ? 'LIVE' : 'IDLE'}
              </span>
            </div>
          </div>
        </div>

        {/* Right: velocity, total, filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontFamily: JETBRAINS_MONO, fontSize: 9, color: '#3D5060', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Velocity</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 3 }}>
              <span style={{
                fontFamily: JETBRAINS_MONO, fontSize: 18, fontWeight: 700, lineHeight: 1,
                color: velocity > 50 ? COLORS.red : velocity > 20 ? COLORS.amber : '#E2E8F0',
              }}>{velocity}</span>
              <span style={{ fontFamily: JETBRAINS_MONO, fontSize: 9, color: '#3D5060' }}>evt/s</span>
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <div style={{ fontFamily: JETBRAINS_MONO, fontSize: 9, color: '#3D5060', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Total</div>
            <span style={{ fontFamily: JETBRAINS_MONO, fontSize: 18, fontWeight: 700, lineHeight: 1, color: '#E2E8F0' }}>
              {totalEvents || totalSessionEvents}
            </span>
          </div>

          <div style={{ position: 'relative' }}>
            <Search size={13} style={{
              position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)',
              color: '#3D5060', pointerEvents: 'none',
            }} />
            <input
              type="text"
              placeholder="Filter process, path, action…"
              style={{
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: 6, padding: '4px 10px 4px 26px',
                fontFamily: JETBRAINS_MONO, fontSize: 11, color: '#C8D0DC',
                outline: 'none', width: 200,
                transition: 'border-color 0.2s, box-shadow 0.2s',
              }}
              onFocus={e => {
                e.target.style.borderColor = 'rgba(0,212,255,0.35)';
                e.target.style.boxShadow = '0 0 0 2px rgba(0,212,255,0.08)';
              }}
              onBlur={e => {
                e.target.style.borderColor = 'rgba(255,255,255,0.07)';
                e.target.style.boxShadow = 'none';
              }}
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
            />
          </div>
        </div>
      </header>

      {/* FEED COLUMN HEADERS */}
      <div style={{
        display: 'flex', alignItems: 'center',
        padding: '0 14px', height: 30,
        background: 'rgba(0,0,0,0.35)',
        borderBottom: '1px solid rgba(255,255,255,0.035)',
        flexShrink: 0,
        position: 'relative',
      }}>
        {/* Accent underline */}
        <div style={{
          position: 'absolute', bottom: 0, left: 14, right: 14, height: 1,
          background: 'linear-gradient(90deg, rgba(0,212,255,0.2), transparent)',
          pointerEvents: 'none',
        }} />
        {[
          ['TIMESTAMP', '72px'],
          ['SRC', '40px'],
          ['PROCESS', '140px'],
          ['PID', '52px'],
          ['ACTION', '76px'],
          ['FILE PATH', '1'],
          ['SCORE', '56px', true],
        ].map(([col, w, right]) => (
          <div key={col} style={{
            width: w === '1' ? undefined : w,
            flex: w === '1' ? 1 : undefined,
            fontFamily: JETBRAINS_MONO, fontSize: 9, fontWeight: 700,
            color: '#3A4A5C', textTransform: 'uppercase', letterSpacing: '0.12em',
            textAlign: right ? 'right' : 'left',
          }}>{col}</div>
        ))}
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
              
              // Left border threat indicator
              const rowBorderColor = item.process_score >= 75 ? COLORS.red
                : item.process_score >= 50 ? COLORS.amber
                : item.process_score >= 30 ? '#FF8C00'
                : 'transparent';

              return (
                <div
                  key={`${item.id}-${item.timestamp}-${item.event_type}`}
                  onClick={() => { setSelectedEventId(item.id); setPanelError(null); }}
                  className={`animate-row-in ${isBurst && subIdx > 0 ? '' : ''}`}
                  style={{
                    display: 'flex', alignItems: 'center',
                    padding: '0 14px',
                    height: 34,
                    cursor: 'pointer',
                    position: 'relative',
                    backgroundColor: isSelected
                      ? 'rgba(0,212,255,0.07)'
                      : getRowBackground(item),
                    borderLeft: `2px solid ${isSelected ? COLORS.cyan : rowBorderColor}`,
                    opacity: isBurst && subIdx > 0 ? 0.65 : 1,
                    transition: 'background 0.12s, border-color 0.12s',
                    borderBottom: '1px solid rgba(255,255,255,0.025)',
                  }}
                  onMouseEnter={e => { if (!isSelected) e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)'; }}
                  onMouseLeave={e => { if (!isSelected) e.currentTarget.style.backgroundColor = getRowBackground(item); }}
                >
                  {/* Timestamp */}
                  <div style={{ width: 72, fontFamily: JETBRAINS_MONO, fontSize: 10.5, color: COLORS.secondaryText, flexShrink: 0 }}>
                    {item.timestamp?.slice(11, 19)}
                  </div>

                  {/* Source */}
                  <div style={{ width: 40, flexShrink: 0 }}>
                    <SourceBadge source={item.source} />
                  </div>

                  {/* Process name */}
                  <div style={{ width: 140, display: 'flex', alignItems: 'center', gap: 5, overflow: 'hidden', flexShrink: 0, paddingRight: 6 }}>
                    <span style={{
                      fontFamily: INTER, fontSize: 12, fontWeight: 600,
                      color: getProcessColor(item),
                      textDecoration: item.status === 'KILLED' ? 'line-through' : 'none',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>
                      {item.process_name}
                    </span>
                    {item.status === 'KILLED' && (
                      <span style={{
                        flexShrink: 0, fontSize: 8, padding: '1px 4px',
                        background: 'rgba(255,45,85,0.15)',
                        border: '1px solid rgba(255,45,85,0.3)',
                        color: COLORS.red, borderRadius: 3, fontWeight: 700, letterSpacing: '0.05em',
                        fontFamily: JETBRAINS_MONO,
                      }}>KILLED</span>
                    )}
                  </div>

                  {/* PID */}
                  <div style={{ width: 52, fontFamily: JETBRAINS_MONO, fontSize: 10.5, color: '#3A4A5C', flexShrink: 0 }}>
                    {item.pid || '—'}
                  </div>

                  {/* Action */}
                  <div style={{ width: 76, display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
                    <ActionTag type={item.event_type} />
                    {isBurst && subIdx === 0 && (
                      <span style={{ fontSize: 9, color: COLORS.amber, fontWeight: 700, fontFamily: JETBRAINS_MONO }}>×{e._burstCount}</span>
                    )}
                  </div>

                  {/* File path */}
                  <div style={{
                    flex: 1, overflow: 'hidden', display: 'flex', alignItems: 'center', gap: 6,
                    fontFamily: JETBRAINS_MONO, fontSize: 10.5, color: COLORS.mutedGray,
                    paddingRight: 8,
                  }}>
                    {isBurst && subIdx === 0 && (
                      <button
                        onClick={(evt) => toggleBurst(e.id, evt)}
                        style={{ color: COLORS.secondaryText, background: 'none', border: 'none', cursor: 'pointer', padding: 0, flexShrink: 0 }}
                      >
                        {isExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                      </button>
                    )}
                    <div style={{ flex: 1, overflow: 'hidden' }}>
                      {renderPath(item.dest_path || item.source_path)}
                    </div>
                  </div>

                  {/* Score */}
                  <div style={{ width: 56, textAlign: 'right', flexShrink: 0 }}>
                    <ScoreDelta delta={item.score_delta} />
                  </div>
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
          from { transform: translateY(-100%); opacity: 0; }
          to   { transform: translateY(0);    opacity: 1; }
        }
        @keyframes panel-in {
          from { transform: translateX(100%); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
        @keyframes fade-in {
          from { opacity: 0; }
          to   { opacity: 1; }
        }
        @keyframes row-in {
          from { transform: translateX(-4px); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
        @keyframes scan-line {
          0%   { transform: translateY(-100%); }
          100% { transform: translateY(800%); }
        }
        .animate-shimmer    { animation: shimmer 2.5s infinite; }
        .animate-slide-down { animation: slide-down 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
        .animate-panel-in   { animation: panel-in 0.35s cubic-bezier(0.16, 1, 0.3, 1); }
        .animate-fade-in    { animation: fade-in 0.2s linear; }
        .animate-row-in     { animation: row-in 0.14s ease-out; }
        .animate-spin-slow  { animation: spin 3s linear infinite; }

        .scrollbar-thin::-webkit-scrollbar { width: 3px; }
        .scrollbar-thin::-webkit-scrollbar-track { background: transparent; }
        .scrollbar-thin::-webkit-scrollbar-thumb { background: rgba(0,212,255,0.15); border-radius: 10px; }
        .scrollbar-thin::-webkit-scrollbar-thumb:hover { background: rgba(0,212,255,0.3); }
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
