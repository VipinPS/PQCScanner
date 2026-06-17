import { useState, useEffect, createContext, useContext } from "react";

// ─── User context ─────────────────────────────────────────────────────────────
const UserContext = createContext(null);
const useUser = () => useContext(UserContext);

// ─── API Client ───────────────────────────────────────────────────────────────
async function req(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  if (res.status === 204) return null;
  return res.json();
}
const api = {
  getRepos:           (projectId) => req("GET", `/api/repos/${projectId ? `?project_id=${projectId}` : ""}`),
  addRepo:            (d)  => req("POST",   "/api/repos/", d),
  updateRepo:         (id, d) => req("PATCH", `/api/repos/${id}`, d),
  deleteRepo:         (id) => req("DELETE", `/api/repos/${id}`),
  triggerScan:        (id) => req("POST",   `/api/scans/${id}/trigger`),
  getScanRun:         (id) => req("GET",    `/api/scans/runs/${id}`),
  scanAll:            (projectId) => req("POST", `/api/scans/scan-all${projectId ? `?project_id=${projectId}` : ""}`),
  getFindings:        (p)  => req("GET",    `/api/findings/?${new URLSearchParams(p || {})}`),
  getFindingsSummary: ()   => req("GET",    "/api/findings/summary"),
  getCBOM:            (projectId) => req("GET", `/api/cbom/${projectId ? `?project_id=${projectId}` : ""}`),
  getDashboard:       ()   => req("GET",    "/api/reports/dashboard"),
  exportCDX:          ()   => req("GET",    "/api/cbom/export/cyclonedx"),
  exportCSV:          ()   => fetch("/api/cbom/export/csv", { credentials: "include" }),
  health:             ()   => req("GET",    "/api/health"),
  // Resolution & archive
  updateFindingStatus: (id, d)  => req("PATCH",  `/api/findings/${id}/status`, d),
  archiveFinding:      (id, d)  => req("PATCH",  `/api/findings/${id}/archive`, d),
  restoreFinding:      (id)     => req("PATCH",  `/api/findings/${id}/restore`),
  archiveResolved:     (d)      => req("POST",   "/api/findings/archive-resolved", d),
  getArchivedFindings: (p)      => req("GET",    `/api/findings/archived?${new URLSearchParams(p || {})}`),
  // Agility & playbooks
  getPlaybooks:        ()       => req("GET",    "/api/playbooks/"),
  getPlaybook:         (algo)   => req("GET",    `/api/playbooks/${encodeURIComponent(algo)}`),
  getPlaybookLang:     (a, l)   => req("GET",    `/api/playbooks/${encodeURIComponent(a)}/${l}`),
  // Auth
  login:               (d)      => req("POST",   "/api/auth/login",  d),
  logout:              ()       => req("POST",   "/api/auth/logout"),
  me:                  ()       => req("GET",    "/api/auth/me"),
  // Secrets
  getSecrets:          (p)      => req("GET",    `/api/secrets/?${new URLSearchParams(p || {})}`),
  getSecretsSummary:   ()       => req("GET",    "/api/secrets/summary"),
  // AI validation
  validateFinding:     (id)     => req("POST",   `/api/findings/${id}/validate`),
  getAIStatus:         (id)     => req("GET",    `/api/findings/${id}/ai-status`),
  validateBatch:       (repoId) => req("POST",   `/api/findings/validate-batch${repoId ? `?repo_id=${repoId}` : ""}`),
  // CVE overlay
  getFindingCVEs:      (id)     => req("GET",    `/api/findings/${id}/cves`),
  getCVEStats:         ()       => req("GET",    "/api/findings/cve-stats"),
  enrichCVEs:          (repoId) => req("POST",   `/api/findings/enrich-cves${repoId ? `?repo_id=${repoId}` : ""}`),
  // Projects
  getProjects:         ()       => req("GET",    "/api/projects/"),
  createProject:       (d)      => req("POST",   "/api/projects/", d),
  deleteProject:       (id)     => req("DELETE", `/api/projects/${id}`),
  getProjectRepos:     (id)     => req("GET",    `/api/projects/${id}/repos`),
  assignRepoProject:   (rid, pid) => req("PATCH", `/api/repos/${rid}/project`, { project_id: pid }),
  // Reports
  getCoverageMatrix:   (projectId) => req("GET", `/api/reports/coverage-matrix${projectId ? `?project_id=${projectId}` : ""}`),
  getBlastRadius:      (algo, projectId) => req("GET", `/api/reports/blast-radius?algorithm=${encodeURIComponent(algo)}${projectId ? `&project_id=${projectId}` : ""}`),
  // Artifacts
  getArtifacts:        (repoId)   => req("GET",    `/api/artifacts/?repo_id=${repoId}`),
  deleteArtifact:      (id)       => req("DELETE", `/api/artifacts/${id}`),
  uploadArtifact:      (repoId, formData) => fetch("/api/artifacts/upload", {
    method: "POST", credentials: "include", body: formData,
  }).then(r => r.ok ? r.json() : r.text().then(t => Promise.reject(new Error(t)))),
  // Network / TLS
  getNetworkFindings:  (p)        => req("GET",    `/api/network/?${new URLSearchParams(p || {})}`),
  getNetworkSummary:   ()         => req("GET",    "/api/network/summary"),
  scanEndpoint:        (d)        => req("POST",   "/api/network/scan", d),
  deleteNetworkFinding:(id)       => req("DELETE", `/api/network/${id}`),
  archiveNetworkFinding:(id)      => req("PATCH",  `/api/network/${id}/archive`),
  // Runtime agent (Stage 12 — eBPF)
  getRuntimeHosts:     ()        => req("GET",    "/api/runtime/hosts"),
  registerRuntimeHost: (d)       => req("POST",   "/api/runtime/hosts", d),
  deleteRuntimeHost:   (id)      => req("DELETE", `/api/runtime/hosts/${id}`),
  getRuntimeFindings:  (p)       => req("GET",    `/api/runtime/findings?${new URLSearchParams(p || {})}`),
  getRuntimeSummary:   ()        => req("GET",    "/api/runtime/summary"),
  archiveRuntimeFinding:(id)     => req("PATCH",  `/api/runtime/findings/${id}/archive`),
  // CI/CD
  getCICDConfig:       (repoId)  => req("GET",    `/api/cicd/config/${repoId}`),
  saveCICDConfig:      (repoId, d) => req("PUT",  `/api/cicd/config/${repoId}`, d),
  getCICDGate:         (repoId)  => req("GET",    `/api/cicd/gate/${repoId}`),
  getCICDDeliveries:   (repoId)  => req("GET",    `/api/cicd/deliveries/${repoId}`),
  getCICDStatus:       ()        => req("GET",    "/api/cicd/status"),
};

// ─── Carbon Design Tokens (Gray 100 theme) ────────────────────────────────────
const C = {
  // Backgrounds
  bg:        "#161616",  // $background
  bgHover:   "#1c1c1c",
  layer01:   "#1c1c1c",  // $layer-01
  layer02:   "#262626",  // $layer-02
  layer03:   "#393939",  // $layer-03
  // Borders
  border:    "#393939",  // $border-subtle-01
  borderStrong: "#525252",
  // Text
  text01:    "#f4f4f4",  // $text-primary
  text02:    "#c6c6c6",  // $text-secondary
  text03:    "#6f6f6f",  // $text-placeholder
  textDisabled: "#525252",
  // Interactive
  interactive: "#4589ff", // $interactive
  focus:     "#ffffff",
  // Status
  error:     "#fa4d56",
  warning:   "#f1c21b",
  success:   "#42be65",
  info:      "#4589ff",
  // Risk colors
  risk: {
    CRITICAL:   "#fa4d56", BROKEN:     "#fa4d56",
    HIGH:       "#ff832b", VULNERABLE: "#ff832b",
    MEDIUM:     "#f1c21b", WEAK:       "#f1c21b",
    LOW:        "#42be65", SAFE:       "#42be65",
    MONITOR:    "#4589ff", UNKNOWN:    "#6f6f6f",
  },
  riskBg: {
    CRITICAL:   "#2d0709", BROKEN:     "#2d0709",
    HIGH:       "#2d1a00", VULNERABLE: "#2d1a00",
    MEDIUM:     "#2d2600", WEAK:       "#2d2600",
    LOW:        "#071e0a", SAFE:       "#071e0a",
    MONITOR:    "#001141", UNKNOWN:    "#262626",
  },
};

// ─── Shared Styles ────────────────────────────────────────────────────────────
const S = {
  // IBM Carbon button patterns
  btnPrimary: {
    background: C.interactive, color: "#ffffff", border: "none",
    padding: "0 16px", height: 40, fontSize: 14, fontFamily: "'IBM Plex Sans', sans-serif",
    cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 8,
    fontWeight: 400, letterSpacing: "0.16px",
  },
  btnSecondary: {
    background: C.layer02, color: C.text01, border: `1px solid ${C.borderStrong}`,
    padding: "0 16px", height: 40, fontSize: 14, fontFamily: "'IBM Plex Sans', sans-serif",
    cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 8,
  },
  btnGhost: {
    background: "transparent", color: C.interactive, border: "none",
    padding: "0 16px", height: 32, fontSize: 14, fontFamily: "'IBM Plex Sans', sans-serif",
    cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 4,
  },
  btnDanger: {
    background: "transparent", color: C.error, border: "none",
    padding: "0 16px", height: 32, fontSize: 14, fontFamily: "'IBM Plex Sans', sans-serif",
    cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 4,
  },
  input: {
    width: "100%", height: 40, background: C.layer02, border: "none",
    borderBottom: `1px solid ${C.borderStrong}`, color: C.text01,
    padding: "0 16px", fontSize: 14, fontFamily: "'IBM Plex Sans', sans-serif",
    outline: "none", boxSizing: "border-box",
  },
  select: {
    height: 40, background: C.layer02, border: "none",
    borderBottom: `1px solid ${C.borderStrong}`, color: C.text01,
    padding: "0 40px 0 16px", fontSize: 14, fontFamily: "'IBM Plex Sans', sans-serif",
    outline: "none", cursor: "pointer", appearance: "none",
    backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 16 16'%3E%3Cpath fill='%23c6c6c6' d='M8 11L3 6h10z'/%3E%3C/svg%3E")`,
    backgroundRepeat: "no-repeat", backgroundPosition: "right 12px center",
  },
  label: {
    display: "block", fontSize: 12, fontWeight: 400, letterSpacing: "0.32px",
    color: C.text02, marginBottom: 8,
  },
  tile: {
    background: C.layer01, padding: 16, borderTop: `1px solid ${C.border}`,
  },
  input: {
    width: "100%", height: 40, background: C.layer02, border: "none",
    borderBottom: `1px solid ${C.borderStrong}`, color: C.text01,
    padding: "0 12px", fontSize: 14, fontFamily: "'IBM Plex Sans', sans-serif",
    outline: "none",
  },
  tableHeader: {
    background: C.layer02, padding: "14px 16px", fontSize: 12,
    fontWeight: 600, color: C.text02, letterSpacing: "0.32px",
    borderBottom: `1px solid ${C.border}`, textAlign: "left",
    whiteSpace: "nowrap",
  },
  tableCell: {
    padding: "14px 16px", fontSize: 14, color: C.text01,
    borderBottom: `1px solid ${C.border}`, verticalAlign: "middle",
  },
};

// ─── Carbon Tag component ─────────────────────────────────────────────────────
function Tag({ value, small }) {
  const c = C.risk[value] || C.text03;
  const bg = C.riskBg[value] || C.layer02;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      background: bg, color: c,
      border: `1px solid ${c}33`,
      padding: small ? "0 6px" : "0 8px",
      height: small ? 18 : 22,
      fontSize: small ? 10 : 12,
      fontWeight: 400, letterSpacing: "0.32px",
      whiteSpace: "nowrap",
    }}>{value}</span>
  );
}

// ─── Notification ─────────────────────────────────────────────────────────────
function Notification({ kind, title, subtitle, onClose }) {
  const colors = { error: C.error, warning: C.warning, success: C.success, info: C.info };
  const c = colors[kind] || C.info;
  useEffect(() => {
    if (!onClose) return;
    const t = setTimeout(onClose, 3000);
    return () => clearTimeout(t);
  }, []);
  return (
    <div style={{
      background: C.layer01, borderLeft: `4px solid ${c}`,
      padding: "14px 16px", marginBottom: 16,
      display: "flex", justifyContent: "space-between", alignItems: "flex-start",
    }}>
      <div>
        <div style={{ fontSize: 14, fontWeight: 600, color: C.text01 }}>{title}</div>
        {subtitle && <div style={{ fontSize: 14, color: C.text02, marginTop: 4 }}>{subtitle}</div>}
      </div>
      {onClose && (
        <button onClick={onClose} style={{ background: "none", border: "none", color: C.text02, cursor: "pointer", fontSize: 18, lineHeight: 1 }}>×</button>
      )}
    </div>
  );
}

// ─── Progress Bar ─────────────────────────────────────────────────────────────
function ProgressBar({ value, color }) {
  return (
    <div style={{ height: 8, background: C.layer03, width: "100%" }}>
      <div style={{ height: "100%", width: `${Math.min(value, 100)}%`, background: color || C.interactive, transition: "width 0.8s ease" }} />
    </div>
  );
}

// ─── Modal ────────────────────────────────────────────────────────────────────
function Modal({ open, title, onSubmit, onClose, children, submitLabel = "Submit" }) {
  if (!open) return null;
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 9000, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div onClick={onClose} style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,0.65)" }} />
      <div style={{ position: "relative", zIndex: 1, background: C.layer01, width: 560, maxWidth: "95vw", maxHeight: "90vh", overflow: "auto" }}>
        <div style={{ padding: "16px 48px 16px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", justifyContent: "space-between" }}>
          <h3 style={{ margin: 0, fontSize: 20, fontWeight: 400, color: C.text01 }}>{title}</h3>
          <button onClick={onClose} style={{ background: "none", border: "none", color: C.text02, cursor: "pointer", fontSize: 20, position: "absolute", right: 16, top: 14 }}>×</button>
        </div>
        <div style={{ padding: 16 }}>{children}</div>
        <div style={{ padding: 16, borderTop: `1px solid ${C.border}`, display: "flex", justifyContent: "flex-end", gap: 1 }}>
          <button onClick={onClose} style={{ ...S.btnSecondary }}>Cancel</button>
          <button onClick={onSubmit} style={{ ...S.btnPrimary, marginLeft: 1 }}>{submitLabel}</button>
        </div>
      </div>
    </div>
  );
}

// ─── FormField ────────────────────────────────────────────────────────────────
function FormField({ label, children }) {
  return <div style={{ marginBottom: 20 }}><label style={S.label}>{label}</label>{children}</div>;
}

// ─── DataTable ────────────────────────────────────────────────────────────────
function DataTable({ headers, rows, emptyText }) {
  const [search, setSearch] = useState("");
  const filtered = rows.filter(r => {
    if (!search) return true;
    const q = search.toLowerCase();
    // Prefer explicit _search field; fall back to any plain string values
    if (r._search) return r._search.toLowerCase().includes(q);
    return Object.values(r).some(v => typeof v === "string" && v.toLowerCase().includes(q));
  });
  return (
    <div style={{ background: C.layer01, minHeight: "calc(100vh - 380px)" }}>
      {/* Toolbar */}
      <div style={{ background: C.layer02, padding: "0 16px", display: "flex", alignItems: "center", height: 48, borderBottom: `1px solid ${C.border}` }}>
        <div style={{ position: "relative", flex: 1, maxWidth: 320 }}>
          <span style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", color: C.text03, fontSize: 16 }}>🔍</span>
          <input
            placeholder="Search..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ ...S.input, paddingLeft: 36, height: 32, fontSize: 13, borderBottom: "none", background: C.layer03 }}
          />
        </div>
      </div>
      {/* Table */}
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              {headers.map(h => <th key={h.key} style={S.tableHeader}>{h.label}</th>)}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={headers.length} style={{ ...S.tableCell, textAlign: "center", padding: "48px 16px", color: C.text03 }}>{emptyText || "No data."}</td></tr>
            ) : (
              filtered.map((row, i) => (
                <tr key={row.id || i} style={{ background: i % 2 === 0 ? C.layer01 : C.layer02 }}
                  onMouseEnter={e => e.currentTarget.style.background = C.layer03}
                  onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? C.layer01 : C.layer02}>
                  {headers.map(h => <td key={h.key} style={S.tableCell}>{row[h.key]}</td>)}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Section Header ───────────────────────────────────────────────────────────
function PageHeader({ title, description, action }) {
  return (
    <div style={{ padding: "32px 0 24px", display: "flex", justifyContent: "space-between", alignItems: "flex-end", borderBottom: `1px solid ${C.border}`, marginBottom: 24 }}>
      <div>
        <h2 style={{ margin: 0, fontSize: 28, fontWeight: 300, color: C.text01, letterSpacing: "-0.5px" }}>{title}</h2>
        {description && <p style={{ margin: "4px 0 0", fontSize: 14, color: C.text02 }}>{description}</p>}
      </div>
      {action}
    </div>
  );
}

// ─── Stat Tile ────────────────────────────────────────────────────────────────
function StatTile({ label, value, accent, sub }) {
  return (
    <div style={{ ...S.tile, borderTop: `3px solid ${accent || C.interactive}`, flex: 1, minWidth: 140 }}>
      <div style={{ fontSize: 42, fontWeight: 300, color: accent || C.interactive, lineHeight: 1, fontFamily: "'IBM Plex Sans', sans-serif" }}>
        {value ?? "—"}
      </div>
      <div style={{ fontSize: 12, color: C.text02, marginTop: 8, letterSpacing: "0.32px" }}>{label}</div>
      {sub && <div style={{ fontSize: 11, color: C.text03, marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

// ─── Loading ──────────────────────────────────────────────────────────────────
function Loader({ text = "Loading…" }) {
  return (
    <div style={{ padding: 48, textAlign: "center", color: C.text03 }}>
      <div style={{ width: 40, height: 40, border: `3px solid ${C.layer03}`, borderTop: `3px solid ${C.interactive}`, borderRadius: "50%", animation: "spin 0.8s linear infinite", margin: "0 auto 12px" }} />
      <div style={{ fontSize: 14 }}>{text}</div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// VIEWS
// ─────────────────────────────────────────────────────────────────────────────

// ── Blast Radius Modal ────────────────────────────────────────────────────────
function BlastRadiusModal({ algorithm, projectId, onClose }) {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [hover,   setHover]   = useState(null); // hovered repo id

  useEffect(() => {
    api.getBlastRadius(algorithm, projectId)
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [algorithm]);

  const _STATUS_COLOR = {
    BROKEN:     { bg:"#2d0709", border:"#fa4d56", text:"#fa4d56" },
    VULNERABLE: { bg:"#2d1a00", border:"#ff832b", text:"#ff832b" },
    WEAK:       { bg:"#2d2600", border:"#f1c21b", text:"#f1c21b" },
    MONITOR:    { bg:"#001141", border:"#4589ff", text:"#4589ff" },
    SAFE:       { bg:"#071e0a", border:"#42be65", text:"#42be65" },
    UNKNOWN:    { bg:"#262626", border:"#6f6f6f", text:"#6f6f6f" },
  };
  const _RISK_COLOR = {
    CRITICAL: "#fa4d56", HIGH: "#ff832b", MEDIUM: "#f1c21b",
    LOW: "#42be65", UNKNOWN: "#6f6f6f",
  };

  // ── SVG hub-and-spoke layout ──────────────────────────────────────────────
  const SVG_W = 580, SVG_H = 400;
  const CX = SVG_W / 2, CY = SVG_H / 2;
  const ORBIT_R = 160;
  const MAX_GRAPH_REPOS = 14; // cap spokes to keep it readable

  const buildGraph = (repos) => {
    if (!repos || repos.length === 0) return [];
    const n = Math.min(repos.length, MAX_GRAPH_REPOS);
    const maxCount = Math.max(...repos.slice(0, n).map(r => r.finding_count), 1);
    return repos.slice(0, n).map((repo, i) => {
      const angle = (2 * Math.PI * i / n) - Math.PI / 2;
      const x = CX + ORBIT_R * Math.cos(angle);
      const y = CY + ORBIT_R * Math.sin(angle);
      // Node radius: 16–30, proportional to finding_count
      const r = 16 + Math.round((repo.finding_count / maxCount) * 14);
      return { ...repo, x, y, r };
    });
  };

  const centerSc  = data ? (_STATUS_COLOR[data.quantum_status] || _STATUS_COLOR.UNKNOWN) : _STATUS_COLOR.UNKNOWN;
  const graphNodes = data ? buildGraph(data.repos) : [];

  return (
    <div style={{ position:"fixed", inset:0, zIndex:9500, display:"flex",
                  alignItems:"center", justifyContent:"center" }}>
      <div onClick={onClose} style={{ position:"absolute", inset:0, background:"rgba(0,0,0,0.72)" }} />
      <div style={{ position:"relative", zIndex:1, background:C.layer01,
                    width:780, maxWidth:"96vw", maxHeight:"92vh",
                    display:"flex", flexDirection:"column", overflow:"hidden",
                    border:`1px solid ${C.border}` }}>

        {/* ── Header ── */}
        <div style={{ padding:"14px 48px 14px 18px", borderBottom:`1px solid ${C.border}`,
                      display:"flex", alignItems:"center", gap:14, flexShrink:0 }}>
          <span style={{ fontSize:20 }}>🎯</span>
          <div style={{ flex:1 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10 }}>
              <strong style={{ fontSize:16, color:C.text01 }}>Blast Radius — {algorithm}</strong>
              {data?.quantum_status && (
                <span style={{ fontSize:11, padding:"2px 8px",
                  background: centerSc.bg, color: centerSc.text,
                  border:`1px solid ${centerSc.border}44` }}>{data.quantum_status}</span>
              )}
            </div>
            {data?.nist_replacement && (
              <div style={{ fontSize:11, color:C.text03, marginTop:2 }}>
                Replace with: <span style={{ color:C.success }}>{data.nist_replacement}</span>
              </div>
            )}
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none",
            color:C.text02, cursor:"pointer", fontSize:20, position:"absolute",
            right:16, top:12 }}>×</button>
        </div>

        {loading && <Loader text="Calculating blast radius…" />}

        {!loading && data && (
          <div style={{ display:"flex", flex:1, overflow:"hidden" }}>

            {/* ── Left: SVG graph ── */}
            <div style={{ flex:"0 0 auto", borderRight:`1px solid ${C.border}`,
                          background:C.bg, display:"flex", flexDirection:"column",
                          alignItems:"center", justifyContent:"flex-start", padding:"12px 0 0" }}>
              {/* Summary chips */}
              <div style={{ display:"flex", gap:8, marginBottom:10, paddingLeft:16, paddingRight:16 }}>
                <div style={{ textAlign:"center", background:C.layer02,
                               border:`1px solid ${C.border}`, padding:"6px 14px" }}>
                  <div style={{ fontSize:22, fontWeight:300,
                                 color: centerSc.text }}>{data.total_repos}</div>
                  <div style={{ fontSize:10, color:C.text03 }}>repos impacted</div>
                </div>
                <div style={{ textAlign:"center", background:C.layer02,
                               border:`1px solid ${C.border}`, padding:"6px 14px" }}>
                  <div style={{ fontSize:22, fontWeight:300,
                                 color: centerSc.text }}>{data.total_findings}</div>
                  <div style={{ fontSize:10, color:C.text03 }}>total findings</div>
                </div>
              </div>

              {/* SVG hub-and-spoke */}
              <svg width={SVG_W} height={SVG_H} style={{ display:"block" }}>
                {/* Orbit ring (decorative) */}
                <circle cx={CX} cy={CY} r={ORBIT_R}
                  fill="none" stroke={C.border} strokeWidth={0.5} strokeDasharray="4 4" />

                {/* Spokes */}
                {graphNodes.map(node => (
                  <line key={node.id}
                    x1={CX} y1={CY} x2={node.x} y2={node.y}
                    stroke={hover === node.id
                      ? (_RISK_COLOR[node.risk_level] || C.border)
                      : C.border}
                    strokeWidth={hover === node.id ? 2 : 1}
                    strokeOpacity={0.7}
                  />
                ))}

                {/* Center node — algorithm */}
                <ellipse cx={CX} cy={CY} rx={62} ry={30}
                  fill={centerSc.bg}
                  stroke={centerSc.border}
                  strokeWidth={1.5} />
                <text x={CX} y={CY - 6} textAnchor="middle"
                  fill={centerSc.text} fontSize={11} fontWeight={700}
                  fontFamily="'IBM Plex Mono',monospace">
                  {algorithm.length > 14 ? algorithm.slice(0, 13) + "…" : algorithm}
                </text>
                <text x={CX} y={CY + 9} textAnchor="middle"
                  fill={centerSc.text} fontSize={9} opacity={0.8}
                  fontFamily="'IBM Plex Sans',sans-serif">
                  {data.quantum_status}
                </text>

                {/* Repo nodes */}
                {graphNodes.map(node => {
                  const rc  = _RISK_COLOR[node.risk_level] || "#6f6f6f";
                  const rBg = C.riskBg[node.risk_level]   || C.layer02;
                  const isHovered = hover === node.id;
                  const label = node.name.length > 12 ? node.name.slice(0, 11) + "…" : node.name;
                  return (
                    <g key={node.id}
                      onMouseEnter={() => setHover(node.id)}
                      onMouseLeave={() => setHover(null)}
                      style={{ cursor:"default" }}>
                      <circle cx={node.x} cy={node.y} r={node.r + (isHovered ? 3 : 0)}
                        fill={rBg} stroke={rc}
                        strokeWidth={isHovered ? 2 : 1.5} />
                      <text x={node.x} y={node.y - 3} textAnchor="middle"
                        fill={rc} fontSize={8} fontWeight={600}
                        fontFamily="'IBM Plex Sans',sans-serif">
                        {label}
                      </text>
                      <text x={node.x} y={node.y + 9} textAnchor="middle"
                        fill={rc} fontSize={9} fontWeight={700}
                        fontFamily="'IBM Plex Sans',sans-serif">
                        {node.finding_count}
                      </text>
                    </g>
                  );
                })}

                {/* "N more" label if repos truncated */}
                {data.repos.length > MAX_GRAPH_REPOS && (
                  <text x={CX} y={SVG_H - 10} textAnchor="middle"
                    fill={C.text03} fontSize={10}
                    fontFamily="'IBM Plex Sans',sans-serif">
                    + {data.repos.length - MAX_GRAPH_REPOS} more repos — see list →
                  </text>
                )}
              </svg>

              {/* Legend */}
              <div style={{ display:"flex", gap:10, padding:"8px 16px", flexWrap:"wrap",
                             justifyContent:"center", borderTop:`1px solid ${C.border}`,
                             width:"100%", boxSizing:"border-box" }}>
                {["CRITICAL","HIGH","MEDIUM","LOW"].map(k => (
                  <div key={k} style={{ display:"flex", alignItems:"center", gap:4 }}>
                    <div style={{ width:10, height:10, borderRadius:"50%",
                                   background:C.riskBg[k]||C.layer02,
                                   border:`1.5px solid ${_RISK_COLOR[k]||C.text03}` }} />
                    <span style={{ fontSize:9, color:_RISK_COLOR[k]||C.text03 }}>{k}</span>
                  </div>
                ))}
                <div style={{ fontSize:9, color:C.text03 }}>
                  Node size = finding count
                </div>
              </div>
            </div>

            {/* ── Right: sorted repo list ── */}
            <div style={{ flex:1, overflowY:"auto" }}>
              <div style={{ padding:"10px 14px 6px", fontSize:11, fontWeight:600,
                             color:C.text03, letterSpacing:"0.5px",
                             borderBottom:`1px solid ${C.border}`, background:C.layer02 }}>
                AFFECTED REPOSITORIES — sorted by impact
              </div>
              {data.repos.length === 0 ? (
                <div style={{ padding:"40px 0", textAlign:"center", color:C.text03, fontSize:13 }}>
                  No findings for this algorithm.
                </div>
              ) : (
                data.repos.map((repo, i) => {
                  const rc    = _RISK_COLOR[repo.risk_level]  || "#6f6f6f";
                  const sc    = _STATUS_COLOR[repo.worst_status] || _STATUS_COLOR.UNKNOWN;
                  const maxFC = data.repos[0].finding_count || 1;
                  const barPct = Math.round((repo.finding_count / maxFC) * 100);
                  const isH   = hover === repo.id;
                  return (
                    <div key={repo.id}
                      onMouseEnter={() => setHover(repo.id)}
                      onMouseLeave={() => setHover(null)}
                      style={{ padding:"10px 14px",
                               background: isH ? C.layer03 : (i%2===0 ? C.layer01 : C.layer02),
                               borderBottom:`1px solid ${C.border}`,
                               transition:"background 0.1s" }}>
                      <div style={{ display:"flex", alignItems:"center",
                                     justifyContent:"space-between", marginBottom:5 }}>
                        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                          <span style={{ fontSize:10, color:C.text03 }}>#{i+1}</span>
                          <span style={{ fontSize:13, fontWeight:600, color:C.text01 }}>
                            {repo.name}
                          </span>
                          <span style={{ fontSize:10, padding:"1px 5px",
                            background:`${rc}18`, color:rc, border:`1px solid ${rc}33` }}>
                            {repo.risk_level}
                          </span>
                          <span style={{ fontSize:10, padding:"1px 5px",
                            background:sc.bg, color:sc.text, border:`1px solid ${sc.border}44` }}>
                            {repo.worst_status}
                          </span>
                        </div>
                        <span style={{ fontSize:13, fontWeight:700, color:sc.text,
                                        whiteSpace:"nowrap" }}>
                          {repo.finding_count} finding{repo.finding_count !== 1 ? "s" : ""}
                        </span>
                      </div>
                      {/* Impact bar */}
                      <div style={{ height:4, background:C.layer03, borderRadius:2 }}>
                        <div style={{ height:"100%", width:`${barPct}%`,
                                       background:sc.text, borderRadius:2,
                                       transition:"width 0.4s ease" }} />
                      </div>
                      {/* Source type chips */}
                      <div style={{ display:"flex", gap:5, marginTop:5 }}>
                        {repo.source_types.map(st => (
                          <span key={st} style={{ fontSize:9, padding:"1px 5px",
                            background:C.layer03, color:C.text03,
                            border:`1px solid ${C.border}` }}>
                            {st === "source_code" ? "src" : st === "dependency" ? "dep" : st}
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function DashboardView() {
  const user = useUser();
  const [data,       setData]       = useState(null);
  const [summary,    setSummary]    = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [err,        setErr]        = useState(null);
  const [scanning,   setScanning]   = useState(false);
  const [scanToast,  setScanToast]  = useState(null);
  const [matrix,     setMatrix]     = useState(null);
  const [blastAlgo,  setBlastAlgo]  = useState(null);

  const load = () => Promise.all([api.getDashboard(), api.getFindingsSummary(), api.getCoverageMatrix()])
    .then(([d, s, m]) => { setData(d); setSummary(s); setMatrix(m); setLoading(false); })
    .catch(e => { setErr(e.message); setLoading(false); });

  useEffect(() => { load(); }, []);

  const handleScanAll = async () => {
    setScanning(true);
    try {
      const res = await api.scanAll();
      setScanToast({
        kind: "success",
        title: `Scan All queued — ${res.scan_count} repo${res.scan_count !== 1 ? "s" : ""}` +
               (res.artifact_count ? ` + ${res.artifact_count} artifact${res.artifact_count !== 1 ? "s" : ""}` : ""),
        subtitle: `Engine: ${res.engine}`,
      });
    } catch (e) {
      setScanToast({ kind: "error", title: "Scan All failed", subtitle: e.message });
    } finally {
      setScanning(false);
    }
  };

  if (loading) return <Loader text="Loading dashboard…" />;
  if (err) return <Notification kind="error" title="API Error" subtitle={err} />;

  const total     = Math.max(data?.total_findings || 0, 1);
  const depCount  = summary?.by_source?.dependency   || 0;
  const srcCount  = summary?.by_source?.source_code  || 0;
  const artCount  = summary?.by_source?.artifact     || 0;

  const cgCovPct  = data?.call_graph_coverage_pct ?? 0;
  const artCovPct = data?.artifact_coverage_pct   ?? 0;

  return (
    <div>
      {blastAlgo && (
        <BlastRadiusModal algorithm={blastAlgo} onClose={() => setBlastAlgo(null)} />
      )}
      {scanToast && (
        <div style={{ position:"fixed", top:56, right:16, zIndex:9999, minWidth:320 }}>
          <Notification {...scanToast} onClose={() => setScanToast(null)} />
        </div>
      )}
      <PageHeader title="Dashboard" description="Live post-quantum cryptography posture overview"
        action={user?.role === "admin" ? (
          <button onClick={handleScanAll} disabled={scanning}
            style={{ ...S.btnPrimary, opacity: scanning ? 0.6 : 1 }}>
            {scanning ? "Queuing…" : "▶ Scan All"}
          </button>
        ) : null} />

      {/* ── Stat tiles row 1: core ── */}
      <div style={{ display: "flex", gap: 2, flexWrap: "wrap", marginBottom: 2 }}>
        <StatTile label="Repositories"        value={data?.total_repos}    accent={C.interactive} />
        <StatTile label="Critical Repos"      value={data?.critical_repos} accent={C.error} />
        <StatTile label="Total Findings"      value={data?.total_findings} accent={C.warning} />
        <StatTile label="Source Code"         value={srcCount}             accent={C.warning} />
        <StatTile label="Dependency Findings" value={depCount}             accent="#ff832b" />
        <StatTile label="Broken Algorithms"   value={data?.broken}         accent={C.error} />
        <StatTile label="CBOM Entries"        value={data?.cbom_entries}   accent="#a56eff" />
      </div>

      {/* ── Stat tiles row 2: Phase 4/5 coverage ── */}
      <div style={{ display: "flex", gap: 2, flexWrap: "wrap", marginBottom: 24 }}>
        <StatTile label="Artifact Scans"
          value={data?.total_artifacts ?? 0}
          accent="#3d8ef8"
          sub={`${data?.artifact_repos ?? 0} repo${(data?.artifact_repos ?? 0) !== 1 ? "s" : ""} covered`} />
        <StatTile label="Artifact Findings"
          value={data?.artifact_findings ?? 0}
          accent="#3d8ef8" />
        <StatTile label="Artifact Coverage"
          value={`${artCovPct}%`}
          accent={artCovPct >= 80 ? C.success : artCovPct >= 40 ? C.warning : C.error}
          sub="repos with artifact scans" />
        <StatTile label="Call Graph Coverage"
          value={`${cgCovPct}%`}
          accent={cgCovPct >= 80 ? C.success : cgCovPct >= 40 ? C.warning : C.error}
          sub={`${data?.call_graph_analyzed ?? 0} findings analysed`} />
        <StatTile label="Unreachable Findings"
          value={data?.unreachable_findings ?? 0}
          accent="#f1c21b"
          sub="likely false positives" />
      </div>
      {/* ── Coverage Heatmap ── */}
      {matrix && matrix.repos && matrix.repos.length > 0 && matrix.algorithms && matrix.algorithms.length > 0 && (() => {
        const _STATUS_COLOR = {
          BROKEN:     { bg:"#2d0709", border:"#fa4d5688", text:"#fa4d56" },
          VULNERABLE: { bg:"#2d1a00", border:"#ff832b88", text:"#ff832b" },
          WEAK:       { bg:"#2d2600", border:"#f1c21b88", text:"#f1c21b" },
          MONITOR:    { bg:"#001141", border:"#4589ff88", text:"#4589ff" },
          SAFE:       { bg:"#071e0a", border:"#42be6588", text:"#42be65" },
        };
        const algos = matrix.algorithms.slice(0, 12); // cap columns to 12 for readability
        const repos = matrix.repos.slice(0, 20);      // cap rows to 20

        return (
          <div style={{ ...S.tile, marginBottom:2, overflowX:"auto" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
              <h3 style={{ margin:0, fontSize:16, fontWeight:600, color:C.text01 }}>
                Algorithm × Repo Coverage Heatmap
              </h3>
              <span style={{ fontSize:11, color:C.text03 }}>
                {matrix.repos.length} repo(s) · {matrix.algorithms.length} algorithm(s)
                {matrix.repos.length > 20 || matrix.algorithms.length > 12 ? " (truncated)" : ""}
              </span>
            </div>
            <div style={{ overflowX:"auto" }}>
              <table style={{ borderCollapse:"collapse", fontSize:11, minWidth:"100%" }}>
                <thead>
                  <tr>
                    <th style={{ ...S.tableHeader, fontSize:10, minWidth:120, maxWidth:160,
                                  textAlign:"left", background:C.layer03 }}>Repo</th>
                    {algos.map(algo => (
                      <th key={algo} style={{ ...S.tableHeader, fontSize:10, background:C.layer03,
                                              maxWidth:90, overflow:"hidden", textAlign:"center",
                                              whiteSpace:"normal", lineHeight:1.3, padding:"8px 6px" }}>
                        {algo}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {repos.map((repo, ri) => (
                    <tr key={repo.id}>
                      <td style={{ ...S.tableCell, fontSize:11, fontWeight:500, color:C.text01,
                                    maxWidth:160, overflow:"hidden", textOverflow:"ellipsis",
                                    whiteSpace:"nowrap", background: ri%2===0 ? C.layer01 : C.layer02,
                                    padding:"6px 10px" }}
                          title={repo.name}>{repo.name}</td>
                      {algos.map(algo => {
                        const cell = repo.algorithms?.[algo];
                        if (!cell) {
                          return (
                            <td key={algo} style={{ padding:"6px 4px", textAlign:"center",
                                                    background: ri%2===0 ? C.layer01 : C.layer02,
                                                    border:`1px solid ${C.border}` }}>
                              <span style={{ fontSize:9, color:C.text03 }}>—</span>
                            </td>
                          );
                        }
                        const sc = _STATUS_COLOR[cell.status] || { bg:C.layer02, border:C.border, text:C.text03 };
                        return (
                          <td key={algo} style={{ padding:"4px", textAlign:"center",
                                                  background: ri%2===0 ? C.layer01 : C.layer02,
                                                  border:`1px solid ${C.border}` }}>
                            <div onClick={() => setBlastAlgo(algo)}
                                 style={{ background:sc.bg, border:`1px solid ${sc.border}`,
                                          color:sc.text, fontSize:9, fontWeight:700,
                                          padding:"3px 4px", letterSpacing:"0.5px",
                                          lineHeight:1, whiteSpace:"nowrap", cursor:"pointer" }}
                                 title={`${cell.status} · ${cell.count} finding(s) — click for blast radius`}>
                              {cell.status.slice(0,3)}
                              <span style={{ fontSize:8, opacity:0.7, marginLeft:2 }}>×{cell.count}</span>
                            </div>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {/* Legend */}
            <div style={{ display:"flex", gap:12, marginTop:12, flexWrap:"wrap" }}>
              {Object.entries(_STATUS_COLOR).map(([st, sc]) => (
                <div key={st} style={{ display:"flex", alignItems:"center", gap:5 }}>
                  <div style={{ width:12, height:12, background:sc.bg, border:`1px solid ${sc.border}` }} />
                  <span style={{ fontSize:10, color:sc.text }}>{st}</span>
                </div>
              ))}
              <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                <div style={{ width:12, height:12, background:C.layer02, border:`1px solid ${C.border}` }} />
                <span style={{ fontSize:10, color:C.text03 }}>No usage</span>
              </div>
            </div>
          </div>
        );
      })()}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2 }}>
        <div style={{ ...S.tile }}>
          <h3 style={{ margin: "0 0 20px", fontSize: 16, fontWeight: 600, color: C.text01 }}>Quantum Risk Breakdown</h3>
          {[
            { label: "Broken — replace immediately", val: data?.broken || 0, color: C.error },
            { label: "Quantum vulnerable",           val: data?.vulnerable || 0, color: C.warning },
            { label: "Safe / monitor",               val: data?.safe || 0, color: C.success },
          ].map(b => (
            <div key={b.label} style={{ marginBottom: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6, fontSize: 13 }}>
                <span style={{ color: C.text02 }}>{b.label}</span>
                <span style={{ color: b.color, fontWeight: 600 }}>{b.val} ({Math.round((b.val / total) * 100)}%)</span>
              </div>
              <ProgressBar value={Math.round((b.val / total) * 100)} color={b.color} />
            </div>
          ))}
        </div>
        <div style={{ ...S.tile }}>
          <h3 style={{ margin: "0 0 20px", fontSize: 16, fontWeight: 600, color: C.text01 }}>NIST PQC Standards (2024)</h3>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {["Standard", "Algorithm", "Replaces"].map(h => (
                  <th key={h} style={{ ...S.tableHeader, background: C.layer02 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                { std: "FIPS 203", algo: "ML-KEM",  replaces: "RSA / ECDH key exchange" },
                { std: "FIPS 204", algo: "ML-DSA",  replaces: "RSA-sign / ECDSA signatures" },
                { std: "FIPS 205", algo: "SLH-DSA", replaces: "Stateless hash-based sigs" },
              ].map(r => (
                <tr key={r.std}>
                  <td style={S.tableCell}><Tag value={r.std} /></td>
                  <td style={{ ...S.tableCell, fontWeight: 600 }}>{r.algo}</td>
                  <td style={{ ...S.tableCell, color: C.text02 }}>{r.replaces}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {data?.last_scan_at && (
            <p style={{ fontSize: 12, color: C.text03, marginTop: 16 }}>Last scan: {new Date(data.last_scan_at).toLocaleString()}</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Artifact type badge ───────────────────────────────────────────────────────
const ARTIFACT_LABELS = {
  python_wheel:    { label: "Python Wheel",   color: "#3d8ef8" },
  python_sdist:    { label: "Python sdist",   color: "#3d8ef8" },
  java_jar:        { label: "JAR",            color: "#f1a01e" },
  java_war:        { label: "WAR",            color: "#f1a01e" },
  container_image: { label: "Container",      color: "#8a3ffc" },
  native_elf:      { label: "ELF Binary",     color: "#da1e28" },
  native_pe:       { label: "PE Binary",      color: "#da1e28" },
  unknown:         { label: "Unknown",        color: "#6f6f6f" },
};

const STATUS_STYLES = {
  pending:  { bg: "#262626", color: "#8d8d8d", label: "Pending" },
  scanning: { bg: "#012749", color: "#78a9ff", label: "Scanning…" },
  complete: { bg: "#022d0d", color: "#42be65", label: "Complete" },
  failed:   { bg: "#2d0709", color: "#fa4d56", label: "Failed" },
};

function ArtifactsModal({ repo, onClose }) {
  const [artifacts, setArtifacts] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [file,      setFile]      = useState(null);
  const [error,     setError]     = useState(null);
  const pollRefs = {};

  const load = () => api.getArtifacts(repo.id).then(setArtifacts).catch(() => {});

  useEffect(() => {
    load();
    return () => Object.values(pollRefs).forEach(clearInterval);
  }, [repo.id]);

  // Poll any in-progress artifacts
  useEffect(() => {
    const pending = artifacts.filter(a => a.scan_status === "pending" || a.scan_status === "scanning");
    pending.forEach(a => {
      if (!pollRefs[a.id]) {
        pollRefs[a.id] = setInterval(() => {
          api.getArtifacts(repo.id).then(updated => {
            setArtifacts(updated);
            const still = updated.find(x => x.id === a.id);
            if (!still || (still.scan_status !== "pending" && still.scan_status !== "scanning")) {
              clearInterval(pollRefs[a.id]);
              delete pollRefs[a.id];
            }
          });
        }, 2000);
      }
    });
  }, [artifacts]);

  const upload = async () => {
    if (!file) return;
    setUploading(true);
    setError(null);
    try {
      const fd = new FormData();
      fd.append("repo_id", repo.id);
      fd.append("file", file);
      await api.uploadArtifact(repo.id, fd);
      setFile(null);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setUploading(false);
    }
  };

  const remove = async (id) => {
    await api.deleteArtifact(id).catch(() => {});
    load();
  };

  return (
    <div style={{ position:"fixed", inset:0, zIndex:9000, display:"flex", alignItems:"center", justifyContent:"center" }}>
      <div onClick={onClose} style={{ position:"absolute", inset:0, background:"rgba(0,0,0,0.65)" }} />
      <div style={{ position:"relative", zIndex:1, background:C.layer01, width:680, maxWidth:"95vw",
                    maxHeight:"90vh", display:"flex", flexDirection:"column", overflow:"hidden" }}>
        {/* Header */}
        <div style={{ padding:"16px 48px 16px 16px", borderBottom:`1px solid ${C.border}`,
                      display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <div>
            <h3 style={{ margin:0, fontSize:18, fontWeight:600, color:C.text01 }}>
              📎 Artifacts — {repo.name}
            </h3>
            <div style={{ fontSize:12, color:C.text03, marginTop:2 }}>
              Upload binaries for quantum-vulnerability scanning
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:C.text02,
            cursor:"pointer", fontSize:20, position:"absolute", right:16, top:14 }}>×</button>
        </div>

        {/* Artifact list */}
        <div style={{ flex:1, overflow:"auto", padding:16 }}>
          {artifacts.length === 0 ? (
            <div style={{ textAlign:"center", padding:"32px 0", color:C.text03, fontSize:13 }}>
              No artifacts yet. Upload a .whl, .jar, .war, ELF/PE binary, or container tarball.
            </div>
          ) : (
            <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
              {artifacts.map(a => {
                const typeInfo   = ARTIFACT_LABELS[a.artifact_type] || ARTIFACT_LABELS.unknown;
                const statusInfo = STATUS_STYLES[a.scan_status]     || STATUS_STYLES.pending;
                return (
                  <div key={a.id} style={{ display:"flex", alignItems:"center", gap:10,
                    background:C.layer02, border:`1px solid ${C.border}`, padding:"10px 14px" }}>
                    {/* Type badge */}
                    <span style={{ fontSize:11, padding:"2px 7px", background:`${typeInfo.color}22`,
                      color:typeInfo.color, border:`1px solid ${typeInfo.color}44`, whiteSpace:"nowrap" }}>
                      {typeInfo.label}
                    </span>
                    {/* Name + filename */}
                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ fontSize:13, color:C.text01, fontWeight:500,
                        overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                        {a.name}
                      </div>
                      <div style={{ fontSize:11, color:C.text03 }}>{a.original_filename}</div>
                    </div>
                    {/* Status */}
                    <span style={{ fontSize:11, padding:"2px 8px", background:statusInfo.bg,
                      color:statusInfo.color, whiteSpace:"nowrap" }}>
                      {statusInfo.label}
                    </span>
                    {/* Finding count */}
                    {a.scan_status === "complete" && (
                      <span style={{ fontSize:12, color: a.finding_count > 0 ? "#da1e28" : "#42be65",
                        fontWeight:600, whiteSpace:"nowrap" }}>
                        {a.finding_count} {a.finding_count === 1 ? "finding" : "findings"}
                      </span>
                    )}
                    {/* Size */}
                    <span style={{ fontSize:11, color:C.text03, whiteSpace:"nowrap" }}>
                      {a.size_bytes ? `${(a.size_bytes / 1024).toFixed(0)} KB` : ""}
                    </span>
                    {/* Delete */}
                    <button onClick={() => remove(a.id)}
                      style={{ ...S.btnDanger, padding:"3px 8px", fontSize:11 }}>✕</button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Upload area */}
        <div style={{ borderTop:`1px solid ${C.border}`, padding:16 }}>
          {error && (
            <div style={{ fontSize:12, color:"#fa4d56", marginBottom:8, padding:"6px 10px",
              background:"#2d0709", border:"1px solid #fa4d5644" }}>
              {error}
            </div>
          )}
          <div style={{ display:"flex", gap:8, alignItems:"center" }}>
            <label style={{ flex:1, display:"flex", alignItems:"center", gap:10,
              background:C.layer02, border:`1px dashed ${C.border}`, padding:"10px 14px",
              cursor:"pointer" }}>
              <span style={{ fontSize:20 }}>📁</span>
              <div>
                <div style={{ fontSize:13, color:C.text01 }}>
                  {file ? file.name : "Choose artifact file…"}
                </div>
                <div style={{ fontSize:11, color:C.text03 }}>
                  .whl · .jar · .war · .tar.gz · .rpm · .deb · .so · .a · .aar · .apk · .gem · .nupkg · .zip
                </div>
              </div>
              <input type="file" style={{ display:"none" }}
                accept=".whl,.egg,.jar,.war,.ear,.aar,.apk,.nupkg,.gem,.tar.gz,.tgz,.tar,.rpm,.srpm,.src.rpm,.deb,.udeb,.so,.a,.ko,.dylib,.zip"
                onChange={e => { setFile(e.target.files[0] || null); setError(null); }} />
            </label>
            <button onClick={upload} disabled={!file || uploading}
              style={{ ...S.btnPrimary, opacity: (!file || uploading) ? 0.5 : 1, whiteSpace:"nowrap" }}>
              {uploading ? "Uploading…" : "Upload & Scan"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Dependency Tree Modal ─────────────────────────────────────────────────────
function DepTreeModal({ repo, projectId, onClose }) {
  const [findings, setFindings] = useState([]);
  const [loading,  setLoading]  = useState(true);

  useEffect(() => {
    api.getFindings({ repo_id: repo.id, source_type: "dependency" })
      .then(data => { setFindings(Array.isArray(data) ? data : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [repo.id]);

  // Group: manifest → package key → { name, version, algorithms: [{algorithm, quantum_status, risk_level}] }
  const tree = {};
  for (const f of findings) {
    const manifest = f.file_path || "(unknown manifest)";
    const pkgKey   = `${f.dependency_name}||${f.dependency_version || ""}`;
    if (!tree[manifest]) tree[manifest] = {};
    if (!tree[manifest][pkgKey]) {
      tree[manifest][pkgKey] = { name: f.dependency_name, version: f.dependency_version, algos: [] };
    }
    tree[manifest][pkgKey].algos.push({ algorithm: f.algorithm, quantum_status: f.quantum_status, risk_level: f.risk_level });
  }

  const manifests = Object.keys(tree).sort();
  const _STATUS_RANK = { BROKEN:0, VULNERABLE:1, WEAK:2, MONITOR:3, SAFE:4 };
  const worstStatus = (algos) => algos.reduce((w, a) =>
    (_STATUS_RANK[a.quantum_status] ?? 99) < (_STATUS_RANK[w] ?? 99) ? a.quantum_status : w, "SAFE");

  return (
    <div style={{ position:"fixed", inset:0, zIndex:9000, display:"flex", alignItems:"center", justifyContent:"center" }}>
      <div onClick={onClose} style={{ position:"absolute", inset:0, background:"rgba(0,0,0,0.65)" }} />
      <div style={{ position:"relative", zIndex:1, background:C.layer01, width:720, maxWidth:"95vw",
                    maxHeight:"88vh", display:"flex", flexDirection:"column", overflow:"hidden" }}>
        {/* Header */}
        <div style={{ padding:"14px 48px 14px 16px", borderBottom:`1px solid ${C.border}`,
                      display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <div>
            <h3 style={{ margin:0, fontSize:16, fontWeight:600, color:C.text01 }}>
              🌲 Dependency Tree — {repo.name}
            </h3>
            <div style={{ fontSize:11, color:C.text03, marginTop:2 }}>
              Manifest → Package → Crypto algorithm findings
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:C.text02,
            cursor:"pointer", fontSize:20, position:"absolute", right:16, top:14 }}>×</button>
        </div>

        {/* Body */}
        <div style={{ flex:1, overflowY:"auto", padding:16 }}>
          {loading && <Loader text="Loading dependency findings…" />}
          {!loading && manifests.length === 0 && (
            <div style={{ textAlign:"center", padding:"40px 0", color:C.text03 }}>
              <div style={{ fontSize:28, marginBottom:8 }}>🌲</div>
              {!repo.last_scanned_at ? (
                <>
                  <div style={{ fontSize:13, color:C.text01, fontWeight:600 }}>
                    Repository not yet scanned
                  </div>
                  <div style={{ fontSize:11, marginTop:6, lineHeight:1.6 }}>
                    Run a scan first. The dependency scanner will parse manifest files
                    (requirements.txt, package.json, go.mod, pom.xml…) and flag
                    known crypto-vulnerable packages.
                  </div>
                </>
              ) : (
                <>
                  <div style={{ fontSize:13, color:C.text01, fontWeight:600 }}>
                    No crypto dependency findings
                  </div>
                  <div style={{ fontSize:11, marginTop:6, lineHeight:1.6, maxWidth:420, margin:"6px auto 0" }}>
                    Last scanned: {new Date(repo.last_scanned_at).toLocaleString()}
                    <br />
                    The dependency scanner only flags packages in its known-vulnerable
                    list (e.g. <code style={{ fontFamily:"'IBM Plex Mono',monospace" }}>pycryptodome</code>,{" "}
                    <code style={{ fontFamily:"'IBM Plex Mono',monospace" }}>python-jose</code>,{" "}
                    <code style={{ fontFamily:"'IBM Plex Mono',monospace" }}>cryptography</code>,{" "}
                    <code style={{ fontFamily:"'IBM Plex Mono',monospace" }}>node-forge</code>,
                    etc.). Manifests with no recognised crypto libraries will show no results here.
                  </div>
                </>
              )}
            </div>
          )}
          {!loading && manifests.map(manifest => (
            <div key={manifest} style={{ marginBottom:16 }}>
              {/* Manifest file header */}
              <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6,
                            padding:"6px 10px", background:C.layer02, borderLeft:`3px solid ${C.interactive}` }}>
                <span style={{ fontSize:14, color:C.interactive }}>📄</span>
                <span style={{ fontSize:12, color:C.text01, fontFamily:"'IBM Plex Mono',monospace",
                               fontWeight:600 }}>{manifest}</span>
                <span style={{ marginLeft:"auto", fontSize:11, color:C.text03 }}>
                  {Object.keys(tree[manifest]).length} package(s)
                </span>
              </div>

              {/* Packages */}
              <div style={{ paddingLeft:20, display:"flex", flexDirection:"column", gap:4 }}>
                {Object.values(tree[manifest]).map((pkg, pi) => {
                  const worst = worstStatus(pkg.algos);
                  const wc = C.risk[worst] || C.text03;
                  return (
                    <div key={pi} style={{ background:C.layer02, border:`1px solid ${C.border}`,
                                           borderLeft:`2px solid ${wc}` }}>
                      {/* Package row */}
                      <div style={{ display:"flex", alignItems:"center", gap:8,
                                    padding:"7px 12px", borderBottom: pkg.algos.length ? `1px solid ${C.border}` : "none" }}>
                        <span style={{ fontSize:12, color:C.text03 }}>📦</span>
                        <span style={{ fontSize:13, color:C.text01, fontWeight:600 }}>
                          {pkg.name}
                        </span>
                        {pkg.version && (
                          <span style={{ fontSize:11, color:C.text03, fontFamily:"'IBM Plex Mono',monospace" }}>
                            =={pkg.version}
                          </span>
                        )}
                        {!pkg.version && (
                          <span style={{ fontSize:10, color:"#f1c21b", background:"#f1c21b18",
                                         padding:"1px 5px", border:"1px solid #f1c21b33" }}>unpinned</span>
                        )}
                        <span style={{ marginLeft:"auto", fontSize:10, padding:"1px 6px",
                                       background:`${wc}18`, color:wc, border:`1px solid ${wc}33` }}>
                          {worst}
                        </span>
                      </div>
                      {/* Algorithm rows */}
                      <div style={{ paddingLeft:32, paddingRight:12, paddingTop:4, paddingBottom:4,
                                    display:"flex", flexDirection:"column", gap:3 }}>
                        {pkg.algos.map((a, ai) => (
                          <div key={ai} style={{ display:"flex", alignItems:"center", gap:8, fontSize:11 }}>
                            <span style={{ color:C.text03, fontSize:10 }}>└─</span>
                            <span style={{ color:C.text02, fontFamily:"'IBM Plex Mono',monospace" }}>
                              {a.algorithm}
                            </span>
                            <Tag value={a.quantum_status} small />
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        {!loading && findings.length > 0 && (
          <div style={{ borderTop:`1px solid ${C.border}`, padding:"8px 16px",
                        fontSize:11, color:C.text03, textAlign:"right" }}>
            {findings.length} total dependency findings · {manifests.length} manifest file(s)
          </div>
        )}
      </div>
    </div>
  );
}

// ── Repo list inside a project (drill-down) ──────────────────────────────────
function ProjectReposView({ project, onBack }) {
  const user = useUser();
  const canAdd    = user?.role === "admin";
  const canDelete = user?.role === "admin";
  const canScan   = user?.role === "admin" || user?.role === "dev";

  const [repos,        setRepos]        = useState([]);
  const [allRepos,     setAllRepos]     = useState([]);  // all repos for assign dropdown
  const [allProjects,  setAllProjects]  = useState([]);  // for conflict project name lookup
  const [loading,      setLoading]      = useState(true);
  const [addOpen,      setAddOpen]      = useState(false);
  const [assignOpen,   setAssignOpen]   = useState(false);
  const [assignId,     setAssignId]     = useState("");
  const [urlConflict,  setUrlConflict]  = useState(null); // repo that already has the entered URL
  const [editRepo,     setEditRepo]     = useState(null); // repo being edited
  const [artifactsRepo, setArtifactsRepo] = useState(null); // repo whose artifacts modal is open
  const [scanningAll,   setScanningAll]   = useState(false);
  const [editForm,     setEditForm]     = useState({ name: "", branch: "", provider: "" });
  const [scanning,     setScanning]     = useState({});
  const [toast,        setToast]        = useState(null);
  const [form,         setForm]         = useState({ name: "", url: "", provider: "github", branch: "main" });
  const [depTreeRepo,  setDepTreeRepo]  = useState(null); // repo whose dep tree modal is open

  const load = () => Promise.all([api.getRepos(project.id), api.getRepos(), api.getProjects()])
    .then(([r, all, projs]) => { setRepos(r); setAllRepos(all); setAllProjects(projs); setLoading(false); })
    .catch(e => { setToast({ kind: "error", title: "Load failed", subtitle: e.message }); setLoading(false); });
  useEffect(() => { load(); }, [project.id]);

  const addRepo = async () => {
    // Check for URL collision before hitting the API
    const conflict = allRepos.find(r => r.url.trim() === form.url.trim() && form.url.trim() !== "");
    if (conflict) {
      if (conflict.project_id === project.id) {
        setToast({ kind: "error", title: "Already in this project", subtitle: `"${conflict.name}" is already assigned to this project.` });
        return;
      }
      setUrlConflict(conflict);
      return;
    }
    try {
      await api.addRepo({ ...form, project_id: project.id });
      setAddOpen(false);
      setForm({ name: "", url: "", provider: "github", branch: "main" });
      setToast({ kind: "success", title: "Repository added", subtitle: form.name });
      load();
    } catch (e) { setToast({ kind: "error", title: "Add failed", subtitle: e.message }); }
  };

  const assignConflictingRepo = async () => {
    try {
      await api.assignRepoProject(urlConflict.id, project.id);
      setUrlConflict(null);
      setAddOpen(false);
      setForm({ name: "", url: "", provider: "github", branch: "main" });
      setToast({ kind: "success", title: "Repository assigned", subtitle: urlConflict.name });
      load();
    } catch (e) { setToast({ kind: "error", title: "Assign failed", subtitle: e.message }); }
  };

  const openEdit = (repo) => {
    setEditRepo(repo);
    setEditForm({ name: repo.name, branch: repo.branch || "main", provider: repo.provider || "github" });
  };

  const saveEdit = async () => {
    try {
      await api.updateRepo(editRepo.id, editForm);
      setEditRepo(null);
      setToast({ kind: "success", title: "Repository updated", subtitle: editForm.name });
      load();
    } catch (e) { setToast({ kind: "error", title: "Update failed", subtitle: e.message }); }
  };

  const scan = async (repo) => {
    setScanning(s => ({ ...s, [repo.id]: "queued" }));
    try {
      const { scan_run_id } = await api.triggerScan(repo.id);
      const poll = setInterval(async () => {
        const run = await api.getScanRun(scan_run_id);
        setScanning(s => ({ ...s, [repo.id]: run.status }));
        if (["complete", "failed"].includes(run.status)) {
          clearInterval(poll); load();
          setToast({ kind: run.status === "complete" ? "success" : "error", title: `Scan ${run.status}`, subtitle: `${repo.name} — ${run.total_findings || 0} findings` });
        }
      }, 2000);
    } catch (e) { setScanning(s => ({ ...s, [repo.id]: null })); setToast({ kind: "error", title: "Scan failed", subtitle: e.message }); }
  };

  const headers = [
    { key: "name",     label: "Repository" },
    { key: "provider", label: "Provider" },
    { key: "risk",     label: "Risk Level" },
    { key: "agility",  label: "Agility" },
    { key: "scanned",  label: "Last Scanned" },
    { key: "actions",  label: "Actions" },
  ];

  const rows = repos.map(r => ({
    id: r.id, name: r.name, provider: r.provider,
    risk: <Tag value={r.risk_level} />,
    agility: r.agility_level
      ? <AgilityBadge level={r.agility_level} label={r.agility_label} small />
      : <span style={{ color:C.text03, fontSize:11 }}>—</span>,
    scanned: r.last_scanned_at ? new Date(r.last_scanned_at).toLocaleString() : <span style={{ color: C.text03 }}>Not scanned</span>,
    actions: (
      <div style={{ display: "flex", gap: 4 }}>
        {canScan && (
          <button disabled={!!scanning[r.id]} onClick={() => scan(r)} style={{ ...S.btnGhost, color: scanning[r.id] ? C.text03 : C.success }}>
            ▶ {scanning[r.id] ? scanning[r.id] : "Scan"}
          </button>
        )}
        {canAdd && (
          <>
            <button onClick={() => setDepTreeRepo(r)} style={{ ...S.btnSecondary, fontSize:12 }}>🌲 Deps</button>
            <button onClick={() => setArtifactsRepo(r)} style={{ ...S.btnSecondary, fontSize:12 }}>📎 Artifacts</button>
            <button onClick={() => openEdit(r)} style={{ ...S.btnSecondary, fontSize:12 }}>✎ Edit</button>
          </>
        )}
        {canDelete && (
          <button onClick={() => api.deleteRepo(r.id).then(load)} style={{ ...S.btnDanger }}>✕ Delete</button>
        )}
      </div>
    ),
  }));

  return (
    <div>
      {toast && <div style={{ position: "fixed", top: 56, right: 16, zIndex: 9999, minWidth: 320 }}><Notification {...toast} onClose={() => setToast(null)} /></div>}
      {/* Breadcrumb */}
      <div style={{ display:"flex", alignItems:"center", gap:8, marginTop:24, marginBottom:16, fontSize:13, color:C.text02 }}>
        <button onClick={onBack} style={{ background:"none", border:"none", color:C.interactive,
          cursor:"pointer", fontSize:13, fontFamily:"'IBM Plex Sans',sans-serif", padding:0 }}>
          ← Projects
        </button>
        <span style={{ color:C.text03 }}>/</span>
        <span style={{ color:C.text01, fontWeight:600 }}>{project.name}</span>
        {project.description && <span style={{ color:C.text03 }}>— {project.description}</span>}
      </div>
      <PageHeader title={project.name} description={`Repositories in this project`}
        action={canAdd ? (
          <div style={{ display:"flex", gap:8 }}>
            <button onClick={() => { setAssignId(""); setAssignOpen(true); }} style={S.btnSecondary}>
              ⊕ Assign Existing
            </button>
            <button onClick={() => setAddOpen(true)} style={S.btnSecondary}>+ Add New</button>
            <button disabled={!!scanningAll}
              onClick={async () => {
                setScanningAll(true);
                try {
                  const res = await api.scanAll(project.id);
                  setToast({ kind:"success", title:`▶ Scan All queued — ${res.scan_count} repo${res.scan_count!==1?"s":""}` });
                } catch(e) { setToast({ kind:"error", title:"Scan All failed", subtitle:e.message }); }
                finally { setScanningAll(false); }
              }}
              style={{ ...S.btnPrimary, opacity: scanningAll ? 0.6 : 1 }}>
              {scanningAll ? "Queuing…" : "▶ Scan All"}
            </button>
          </div>
        ) : null} />
      {loading ? <Loader /> : <DataTable headers={headers} rows={rows} emptyText="No repositories in this project yet." />}

      {/* Add new repo modal */}
      <Modal open={addOpen} title="Add Repository" onSubmit={addRepo} onClose={() => { setAddOpen(false); setUrlConflict(null); }} submitLabel="Add Repository">
        {urlConflict ? (
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:12 }}>
              <span style={{ fontSize:18, color:"#f1c21b" }}>⚠</span>
              <span style={{ fontSize:14, fontWeight:600, color:C.text01 }}>Repository URL already registered</span>
            </div>
            <div style={{ background:"#2b2200", border:"1px solid #f1c21b44", padding:"12px 16px", marginBottom:16, fontSize:13, color:C.text01, lineHeight:1.6 }}>
              <strong>"{urlConflict.name}"</strong> already exists with this URL.{" "}
              {urlConflict.project_id
                ? <>It is currently assigned to <strong>"{allProjects.find(p => p.id === urlConflict.project_id)?.name || "another project"}"</strong>. Assigning it here will move it to this project.</>
                : <>It is currently unassigned. You can assign it to this project.</>
              }
            </div>
            <div style={{ display:"flex", gap:8, justifyContent:"flex-end" }}>
              <button onClick={() => setUrlConflict(null)} style={S.btnSecondary}>← Edit URL</button>
              <button onClick={assignConflictingRepo} style={{ ...S.btnPrimary }}>Assign to this project</button>
            </div>
          </div>
        ) : (
          <>
            <FormField label="Repository Name"><input style={S.input} placeholder="auth-service" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} /></FormField>
            <FormField label="Repository URL"><input style={S.input} placeholder="https://github.com/org/repo" value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))} /></FormField>
            <FormField label="Provider">
              <select style={S.select} value={form.provider} onChange={e => setForm(f => ({ ...f, provider: e.target.value }))}>
                {["github", "github-enterprise", "gitlab", "bitbucket", "local"].map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </FormField>
            <FormField label="Branch"><input style={S.input} placeholder="main" value={form.branch} onChange={e => setForm(f => ({ ...f, branch: e.target.value }))} /></FormField>
          </>
        )}
      </Modal>

      {/* Assign existing repo modal */}
      {(() => {
        const selectedRepo = allRepos.find(r => r.id === assignId);
        const selectedInOtherProject = selectedRepo && selectedRepo.project_id && selectedRepo.project_id !== project.id;
        const otherProjectName = selectedInOtherProject ? allProjects.find(p => p.id === selectedRepo.project_id)?.name : null;
        return (
          <Modal open={assignOpen} title="Assign Existing Repository"
            onSubmit={async () => {
              if (!assignId) return;
              try {
                await api.assignRepoProject(assignId, project.id);
                setAssignOpen(false); setAssignId("");
                setToast({ kind: "success", title: "Repository assigned to project" });
                load();
              } catch (e) { setToast({ kind: "error", title: "Failed", subtitle: e.message }); }
            }}
            onClose={() => { setAssignOpen(false); setAssignId(""); }} submitLabel="Assign">
            <FormField label="Select Repository">
              <select style={S.select} value={assignId} onChange={e => setAssignId(e.target.value)}>
                <option value="">— pick a repository —</option>
                {allRepos
                  .filter(r => r.project_id !== project.id)
                  .map(r => <option key={r.id} value={r.id}>{r.name}{r.project_id ? " (in another project)" : ""}</option>)}
              </select>
            </FormField>
            {selectedInOtherProject && (
              <div style={{ display:"flex", alignItems:"flex-start", gap:8, background:"#2b2200", border:"1px solid #f1c21b44", padding:"10px 14px", fontSize:13, color:C.text01, lineHeight:1.6 }}>
                <span style={{ color:"#f1c21b", fontSize:16, flexShrink:0 }}>⚠</span>
                <span>
                  <strong>"{selectedRepo.name}"</strong> is currently in project <strong>"{otherProjectName || "another project"}"</strong>.
                  Assigning it here will <strong>move it</strong> to <strong>"{project.name}"</strong> and remove it from the previous project.
                </span>
              </div>
            )}
          </Modal>
        );
      })()}

      {/* Edit repo modal */}
      <Modal open={!!editRepo} title="Edit Repository" onSubmit={saveEdit} onClose={() => setEditRepo(null)} submitLabel="Save Changes">
        <FormField label="Repository Name">
          <input style={S.input} value={editForm.name} onChange={e => setEditForm(f => ({ ...f, name: e.target.value }))} />
        </FormField>
        <FormField label="Branch">
          <input style={S.input} value={editForm.branch} onChange={e => setEditForm(f => ({ ...f, branch: e.target.value }))} placeholder="main" />
        </FormField>
        <FormField label="Provider">
          <select style={S.select} value={editForm.provider} onChange={e => setEditForm(f => ({ ...f, provider: e.target.value }))}>
            {["github", "github-enterprise", "gitlab", "bitbucket", "local"].map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        </FormField>
      </Modal>

      {/* Artifacts modal */}
      {artifactsRepo && <ArtifactsModal repo={artifactsRepo} onClose={() => setArtifactsRepo(null)} />}
      {/* Dependency tree modal */}
      {depTreeRepo && <DepTreeModal repo={depTreeRepo} onClose={() => setDepTreeRepo(null)} />}
    </div>
  );
}

// ── Projects page (top level) ─────────────────────────────────────────────────
function ProjectsView() {
  const user = useUser();
  const canAdd = user?.role === "admin";

  const [projects,     setProjects]     = useState([]);
  const [loading,      setLoading]      = useState(true);
  const [activeProject, setActiveProject] = useState(null); // drill-down
  const [addOpen,      setAddOpen]      = useState(false);
  const [toast,        setToast]        = useState(null);
  const [form,         setForm]         = useState({ name: "", description: "" });
  const [confirmDelete, setConfirmDelete] = useState(null); // project to confirm delete

  const load = () => api.getProjects()
    .then(p => { setProjects(p); setLoading(false); })
    .catch(e => { setToast({ kind: "error", title: "Load failed", subtitle: e.message }); setLoading(false); });
  useEffect(() => { load(); }, []);

  const createProject = async () => {
    try {
      await api.createProject(form);
      setAddOpen(false);
      setForm({ name: "", description: "" });
      setToast({ kind: "success", title: "Project created", subtitle: form.name });
      load();
    } catch (e) { setToast({ kind: "error", title: "Create failed", subtitle: e.message }); }
  };

  const confirmAndDelete = async () => {
    const p = confirmDelete;
    setConfirmDelete(null);
    try {
      await api.deleteProject(p.id);
      setToast({ kind: "success", title: "Project deleted", subtitle: p.name });
      load();
    } catch (e) { setToast({ kind: "error", title: "Delete failed", subtitle: e.message }); }
  };

  if (activeProject) {
    return <ProjectReposView project={activeProject} onBack={() => { setActiveProject(null); load(); }} />;
  }

  const riskOrder = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, UNKNOWN:4 };

  return (
    <div>
      {toast && <div style={{ position: "fixed", top: 56, right: 16, zIndex: 9999, minWidth: 320 }}><Notification {...toast} onClose={() => setToast(null)} /></div>}
      <PageHeader title="Projects" description="Organise repositories into projects for scoped scanning and reporting"
        action={canAdd ? <button onClick={() => setAddOpen(true)} style={S.btnPrimary}>+ New Project</button> : null} />

      {loading ? <Loader /> : projects.length === 0 ? (
        <div style={{ textAlign:"center", padding:"64px 0", color:C.text03 }}>
          <div style={{ fontSize:32, marginBottom:12 }}>🗂</div>
          <div style={{ fontSize:14 }}>No projects yet. Create one to organise your repositories.</div>
        </div>
      ) : (
        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(320px, 1fr))", gap:12 }}>
          {projects.map(p => {
            const riskColor = C.risk[p.risk_level] || C.text03;
            const riskBg    = C.riskBg[p.risk_level] || C.layer02;
            return (
              <div key={p.id} style={{
                background:C.layer02, border:`1px solid ${C.border}`,
                borderTop:`3px solid ${riskColor}`,
                padding:20, display:"flex", flexDirection:"column", gap:12,
              }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
                  <div>
                    <div style={{ fontSize:16, fontWeight:600, color:C.text01, marginBottom:4 }}>
                      🗂 {p.name}
                    </div>
                    {p.description && (
                      <div style={{ fontSize:12, color:C.text03 }}>{p.description}</div>
                    )}
                  </div>
                  {canAdd && (
                    <button onClick={() => setConfirmDelete(p)} style={{ ...S.btnDanger, fontSize:11, padding:"2px 8px" }}>✕</button>
                  )}
                </div>
                <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                  <span style={{ fontSize:11, padding:"2px 8px", background:riskBg,
                    color:riskColor, border:`1px solid ${riskColor}44` }}>
                    {p.risk_level}
                  </span>
                  <span style={{ fontSize:11, padding:"2px 8px", background:C.layer03,
                    color:C.text02, border:`1px solid ${C.border}` }}>
                    {p.repo_count} {p.repo_count === 1 ? "repo" : "repos"}
                  </span>
                  <span style={{ fontSize:11, color:C.text03 }}>
                    {p.last_scanned_at ? `Scanned ${new Date(p.last_scanned_at).toLocaleDateString()}` : "Not scanned"}
                  </span>
                </div>
                <button onClick={() => setActiveProject(p)} style={{
                  ...S.btnPrimary, width:"100%", justifyContent:"center",
                }}>
                  Open →
                </button>
              </div>
            );
          })}
        </div>
      )}

      <Modal open={addOpen} title="New Project" onSubmit={createProject} onClose={() => setAddOpen(false)} submitLabel="Create Project">
        <FormField label="Project Name"><input style={S.input} placeholder="Payment Services" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} /></FormField>
        <FormField label="Description (optional)"><input style={S.input} placeholder="Brief description…" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} /></FormField>
      </Modal>

      {/* Delete confirmation modal */}
      {confirmDelete && (
        <div style={{ position:"fixed", inset:0, zIndex:9000, display:"flex", alignItems:"center", justifyContent:"center" }}>
          <div onClick={() => setConfirmDelete(null)} style={{ position:"absolute", inset:0, background:"rgba(0,0,0,0.65)" }} />
          <div style={{ position:"relative", zIndex:1, background:C.layer01, width:480, maxWidth:"95vw", padding:24 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:16 }}>
              <span style={{ fontSize:20, color:"#da1e28" }}>⚠</span>
              <h3 style={{ margin:0, fontSize:18, fontWeight:600, color:C.text01 }}>Delete Project</h3>
            </div>
            <p style={{ margin:"0 0 8px", color:C.text01, fontSize:14 }}>
              Are you sure you want to delete <strong>"{confirmDelete.name}"</strong>?
            </p>
            <div style={{ background:"#2d1a1a", border:"1px solid #da1e2844", padding:"12px 16px", marginBottom:20 }}>
              <ul style={{ margin:0, paddingLeft:18, color:"#ff8389", fontSize:13, lineHeight:1.6 }}>
                <li><strong>{confirmDelete.repo_count} {confirmDelete.repo_count === 1 ? "repository" : "repositories"}</strong> will be unlinked from this project</li>
                <li>All associated scan findings and secrets will <strong>remain in the database</strong> but will no longer be grouped under this project</li>
                <li>This action <strong>cannot be undone</strong></li>
              </ul>
            </div>
            <div style={{ display:"flex", justifyContent:"flex-end", gap:8 }}>
              <button onClick={() => setConfirmDelete(null)} style={S.btnSecondary}>Cancel</button>
              <button onClick={confirmAndDelete} style={{ ...S.btnDanger, padding:"8px 16px" }}>Delete Project</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// File path cell — truncated display with copy-to-clipboard
// Works on HTTP (non-localhost) via execCommand fallback
function copyToClipboard(text) {
  // Try modern API first (HTTPS / localhost)
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  // Fallback: create a temporary textarea and execCommand('copy')
  return new Promise((resolve, reject) => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.cssText = "position:fixed;top:-9999px;left:-9999px;opacity:0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try {
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      ok ? resolve() : reject(new Error("execCommand failed"));
    } catch (e) {
      document.body.removeChild(ta);
      reject(e);
    }
  });
}

function FilePath({ path }) {
  const [copied, setCopied] = useState(false);
  const copy = (e) => {
    e.stopPropagation();
    copyToClipboard(path)
      .then(() => { setCopied(true); setTimeout(() => setCopied(false), 1800); })
      .catch(() => {
        // Last resort — show the path in a prompt so user can manually copy
        window.prompt("Copy full path (Ctrl+C / Cmd+C):", path);
      });
  };
  // Show last 2 path segments, full path in title tooltip
  const parts = path ? path.replace(/\\/g, "/").split("/") : [];
  const short = parts.length > 2 ? "…/" + parts.slice(-2).join("/") : path;
  return (
    <div style={{ maxWidth:260 }}>
      <span style={{ fontSize:12, color:C.text02, fontFamily:"'IBM Plex Mono',monospace",
        display:"block", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap",
        cursor:"default" }} title={path}>{short}</span>
      <button onClick={copy} style={{ background:"none", border:"none", padding:0,
        fontSize:10, color: copied ? C.success : C.text03, cursor:"pointer",
        fontFamily:"'IBM Plex Sans',sans-serif", marginTop:1, display:"block" }}>
        {copied ? "✓ copied" : "⎘ copy full path"}
      </button>
    </div>
  );
}

// ── Inline code viewer ────────────────────────────────────────────────────────
function CodeViewer({ context, lineNumber, contextStartLine = 1 }) {
  if (!context) return <p style={{ color: C.text03, fontSize: 12 }}>No code context available.</p>;
  const lines = context.split("\n");
  return (
    <pre style={{
      background: "#0a0a0a", border: `1px solid ${C.border}`,
      borderRadius: 4, padding: "12px 0", margin: 0,
      overflow: "auto", fontSize: 12,
      fontFamily: "'IBM Plex Mono','Courier New',monospace",
      lineHeight: 1.6, maxHeight: 340,
    }}>
      {lines.map((line, i) => {
        const lineNum  = contextStartLine + i;
        const isTarget = lineNum === lineNumber;
        return (
          <div key={i} style={{
            display: "flex",
            background: isTarget ? "#ff832b18" : "transparent",
            borderLeft: isTarget ? "3px solid #ff832b" : "3px solid transparent",
          }}>
            <span style={{
              color: isTarget ? "#ff832b" : "#555",
              minWidth: 44, paddingLeft: 8, paddingRight: 12,
              textAlign: "right", userSelect: "none",
              fontWeight: isTarget ? 700 : 400,
            }}>{lineNum}</span>
            <span style={{ color: isTarget ? "#ffb784" : C.text01, whiteSpace: "pre", paddingRight: 16 }}>
              {line || " "}
            </span>
          </div>
        );
      })}
    </pre>
  );
}

// ── Finding detail panel ──────────────────────────────────────────────────────
function FindingDetailPanel({ finding, allFindings, onClose, onNavigate, repos, onStatusChange, onOpenPlaybook }) {
  const [aiLoading,       setAiLoading]       = useState(false);
  const [aiStatus,        setAiStatus]        = useState(null);
  const [playbook,        setPlaybook]        = useState(null);
  const [playbookLoading, setPlaybookLoading] = useState(false);
  const [copied,          setCopied]          = useState(null);

  const idx   = allFindings.findIndex(f => f.id === finding.id);
  const total = allFindings.length;
  const repo  = repos.find(r => r.id === finding.repo_id);

  // Git deep-link: repo_url/blob/branch/file_path#Lline
  const gitLink = (() => {
    if (!repo?.url || finding.source_type === "dependency") return null;
    const base   = repo.url.replace(/\.git$/, "");
    const branch = repo.branch || "main";
    const line   = finding.line_number ? `#L${finding.line_number}` : "";
    return `${base}/blob/${branch}/${finding.file_path}${line}`;
  })();

  // Fetch playbook for this algorithm
  useEffect(() => {
    if (!finding.algorithm) return;
    setPlaybook(null);
    setPlaybookLoading(true);
    api.getPlaybook(finding.algorithm)
      .then(p => setPlaybook(p))
      .catch(() => setPlaybook(null))
      .finally(() => setPlaybookLoading(false));
  }, [finding.algorithm]);

  // Sync AI status from finding data
  useEffect(() => {
    setAiStatus(null);
    if (finding.ai_label && finding.ai_label !== "pending") {
      setAiStatus({ label: finding.ai_label, confidence: finding.ai_confidence, explanation: finding.ai_explanation });
    }
  }, [finding.id]);

  // Poll while AI validation is pending
  useEffect(() => {
    if (finding.ai_label !== "pending" && !aiLoading) return;
    const iv = setInterval(async () => {
      try {
        const s = await api.getAIStatus(finding.id);
        if (s.ai_label && s.ai_label !== "pending") {
          setAiStatus({ label: s.ai_label, confidence: s.ai_confidence, explanation: s.ai_explanation });
          setAiLoading(false);
          clearInterval(iv);
        }
      } catch {}
    }, 3000);
    return () => clearInterval(iv);
  }, [finding.id, finding.ai_label, aiLoading]);

  const copyText = (text, key) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    }).catch(() => {});
  };

  const triggerValidation = async () => {
    setAiLoading(true);
    try { await api.validateFinding(finding.id); }
    catch (e) { setAiLoading(false); }
  };

  const fname       = finding.file_path?.split("/").pop() || finding.file_path || "";
  const activeAiLabel = aiStatus?.label || finding.ai_label;
  const activeAiConf  = aiStatus?.confidence  ?? finding.ai_confidence;
  const activeAiExp   = aiStatus?.explanation || finding.ai_explanation;
  const isPending     = aiLoading || finding.ai_label === "pending";

  const statusColor = {
    open: "#fa4d56", re_opened: "#ff832b",
    auto_resolved: "#42be65", manually_resolved: "#42be65", false_positive: "#a8a8a8",
  }[finding.migration_status] || C.text03;

  const aiCfg = {
    true_positive:  { color: "#fa4d56", icon: "✓", text: "True Positive"  },
    false_positive: { color: "#42be65", icon: "✗", text: "False Positive" },
    uncertain:      { color: "#f1c21b", icon: "?", text: "Uncertain"       },
    error:          { color: C.text03,  icon: "!", text: "Error"           },
  }[activeAiLabel];

  // Section header style helper
  const sectionLabel = (text) => (
    <div style={{ fontSize: 10, color: C.text03, fontWeight: 600,
        letterSpacing: "0.8px", marginBottom: 10 }}>{text}</div>
  );

  const btn = (label, onClick, color, border) => (
    <button onClick={onClick} style={{
      background: "none", border: `1px solid ${border || color + "44"}`,
      color, padding: "5px 14px", cursor: "pointer",
      fontSize: 12, fontFamily: "'IBM Plex Sans',sans-serif",
    }}>{label}</button>
  );

  return (
    <div style={{
      position: "fixed", right: 0, top: 48, bottom: 0, width: "50vw", minWidth: 640,
      background: C.layer01, borderLeft: `1px solid ${C.border}`,
      overflowY: "auto", zIndex: 200,
      display: "flex", flexDirection: "column",
      boxShadow: "-4px 0 24px #00000060",
    }}>
      {/* ── Sticky header: prev/next + algorithm + tags + close ── */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "10px 16px", borderBottom: `1px solid ${C.border}`,
        background: C.layer02, position: "sticky", top: 0, zIndex: 1, gap: 8,
      }}>
        <div style={{ display: "flex", gap: 4 }}>
          <button onClick={() => onNavigate(-1)} disabled={idx <= 0} style={{
            background: "none", border: `1px solid ${C.border}`, color: C.text01,
            padding: "2px 10px", fontSize: 16, cursor: idx > 0 ? "pointer" : "default",
            opacity: idx > 0 ? 1 : 0.3, fontFamily: "'IBM Plex Sans',sans-serif",
          }}>‹</button>
          <span style={{ fontSize: 11, color: C.text03, alignSelf: "center",
              minWidth: 44, textAlign: "center" }}>{idx + 1} / {total}</span>
          <button onClick={() => onNavigate(1)} disabled={idx >= total - 1} style={{
            background: "none", border: `1px solid ${C.border}`, color: C.text01,
            padding: "2px 10px", fontSize: 16, cursor: idx < total - 1 ? "pointer" : "default",
            opacity: idx < total - 1 ? 1 : 0.3, fontFamily: "'IBM Plex Sans',sans-serif",
          }}>›</button>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
          <strong style={{ fontSize: 14, color: C.text01 }}>{finding.algorithm}</strong>
          <Tag value={finding.risk_level} small />
          <Tag value={finding.quantum_status} small />
          <span style={{ fontSize: 10, fontWeight: 700, padding: "1px 5px",
              background: finding.source_type === "dependency" ? "#ff832b22" : finding.source_type === "artifact" ? "#8a3ffc22" : "#4589ff22",
              color:      finding.source_type === "dependency" ? "#ff832b"   : finding.source_type === "artifact" ? "#be95ff"   : "#4589ff",
              border:     finding.source_type === "dependency" ? "1px solid #ff832b55" : finding.source_type === "artifact" ? "1px solid #be95ff55" : "1px solid #4589ff55",
          }}>
            {finding.source_type === "dependency" ? "DEP" : finding.source_type === "artifact" ? "ART" : "SRC"}
          </span>
          {finding.source_type === "source_code" && finding.reachable === false && (
            <span style={{ fontSize:10, fontWeight:700, padding:"1px 5px",
              background:"#f1c21b22", color:"#f1c21b", border:"1px solid #f1c21b55" }}>
              UNREACHABLE
            </span>
          )}
          {finding.source_type === "source_code" && finding.in_test_path && (
            <span style={{ fontSize:10, fontWeight:700, padding:"1px 5px",
              background:"#8a3ffc22", color:"#be95ff", border:"1px solid #be95ff55" }}>
              TEST/FIXTURE PATH
            </span>
          )}
        </div>
        <button onClick={onClose} style={{
          background: "none", border: "none", color: C.text03,
          fontSize: 20, cursor: "pointer", padding: "0 4px", lineHeight: 1,
        }}>✕</button>
      </div>

      {/* ── Body ── */}
      <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 12 }}>

        {/* ── File / Package ── */}
        <div style={{ background: C.layer02, border: `1px solid ${C.border}`, padding: 12 }}>
          {sectionLabel(finding.source_type === "dependency" ? "DEPENDENCY" : "FILE LOCATION")}
          {finding.source_type === "dependency" ? (
            <>
              <div style={{ fontSize: 14, color: C.text01, fontWeight: 600, marginBottom: 4,
                  fontFamily: "'IBM Plex Mono',monospace" }}>
                {finding.dependency_name}
                <span style={{ color: C.text03, fontWeight: 400, fontSize: 12 }}>
                  {finding.dependency_version ? `==${finding.dependency_version}` : " (unpinned)"}
                </span>
              </div>
              <div style={{ fontSize: 11, color: C.text03 }}>Manifest: {finding.file_path}</div>
            </>
          ) : (
            <>
              <div style={{ fontSize: 12, color: C.text01, fontFamily: "'IBM Plex Mono',monospace",
                  marginBottom: 10 }}>
                {finding.file_path}
                <span style={{ color: C.text03 }}> :{finding.line_number}</span>
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <button onClick={() => copyText(fname, "fname")} style={{
                  background:"none", border:`1px solid ${C.border}`, color: C.text02,
                  padding:"3px 10px", fontSize:11, cursor:"pointer",
                  fontFamily:"'IBM Plex Sans',sans-serif",
                }}>
                  {copied === "fname" ? "✓ Copied" : "⎘ Copy filename"}
                </button>
                <button onClick={() => copyText(finding.file_path, "path")} style={{
                  background:"none", border:`1px solid ${C.border}`, color: C.text02,
                  padding:"3px 10px", fontSize:11, cursor:"pointer",
                  fontFamily:"'IBM Plex Sans',sans-serif",
                }}>
                  {copied === "path" ? "✓ Copied" : "⎘ Copy full path"}
                </button>
                {gitLink && (
                  <a href={gitLink} target="_blank" rel="noopener noreferrer" style={{
                    background:"none", border:`1px solid ${C.interactive}44`,
                    color: C.interactive, padding:"3px 10px", fontSize:11,
                    textDecoration:"none", fontFamily:"'IBM Plex Sans',sans-serif",
                  }}>↗ Open in Git</a>
                )}
              </div>
            </>
          )}
        </div>

        {/* ── CVE Advisories ── */}
        {finding.cves?.length > 0 && (
          <div style={{ background: C.layer02, border: `1px solid ${C.border}`, padding: 12 }}>
            {sectionLabel(`⚠ CVE ADVISORIES (${finding.cves.length})`)}
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {finding.cves.map((cve) => {
                const sevColor = C.risk[cve.cvss_severity] || C.text03;
                return (
                  <div key={cve.id || cve.cve_id} style={{
                    border: `1px solid ${sevColor}44`, background: `${sevColor}11`,
                    padding: "8px 10px",
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: cve.summary ? 4 : 0 }}>
                      <a href={`https://osv.dev/vulnerability/${cve.cve_id}`} target="_blank" rel="noopener noreferrer"
                          style={{ fontSize: 12, fontWeight: 600, color: C.interactive,
                              fontFamily: "'IBM Plex Mono',monospace", textDecoration: "none" }}>
                        {cve.cve_id}
                      </a>
                      {cve.cvss_score != null && (
                        <span style={{ fontSize: 10, fontWeight: 700, padding: "1px 6px",
                            background: `${sevColor}22`, color: sevColor, border: `1px solid ${sevColor}55` }}>
                          CVSS {cve.cvss_score.toFixed(1)}
                        </span>
                      )}
                      {cve.cvss_severity && (
                        <span style={{ fontSize: 10, fontWeight: 700, padding: "1px 6px",
                            background: `${sevColor}22`, color: sevColor, border: `1px solid ${sevColor}55` }}>
                          {cve.cvss_severity}
                        </span>
                      )}
                      <span style={{ fontSize: 10, color: C.text03, marginLeft: "auto" }}>
                        source: {cve.source}
                      </span>
                    </div>
                    {cve.summary && (
                      <div style={{ fontSize: 11, color: C.text02, lineHeight: 1.5 }}>{cve.summary}</div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Code Console ── */}
        {finding.source_type !== "dependency" && finding.context && (
          <div>
            {sectionLabel("CODE CONSOLE")}
            <CodeViewer
              context          = {finding.context}
              lineNumber       = {finding.line_number}
              contextStartLine = {finding.context_start_line || 1}
            />
          </div>
        )}

        {/* ── AI Analysis ── */}
        <div style={{ background: C.layer02, border: `1px solid ${C.border}`, padding: 12 }}>
          {sectionLabel("✦ AI ANALYSIS")}
          {isPending ? (
            <span style={{ fontSize: 12, color: C.text03 }}>⏳ Validating with AI…</span>
          ) : aiCfg ? (
            <>
              <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom: 8 }}>
                <span style={{ fontSize:12, padding:"2px 10px",
                    background:`${aiCfg.color}18`, color: aiCfg.color,
                    border:`1px solid ${aiCfg.color}44` }}>
                  {aiCfg.icon} {aiCfg.text}
                </span>
                {activeAiConf != null && (
                  <span style={{ fontSize:11, color: C.text03 }}>
                    Confidence: <strong style={{ color: C.text01 }}>
                      {Math.round(activeAiConf * 100)}%
                    </strong>
                  </span>
                )}
              </div>
              {activeAiExp && (
                <p style={{ margin:"0 0 10px", fontSize:12, color:C.text01, lineHeight:1.6 }}>
                  {activeAiExp}
                </p>
              )}
              <button onClick={triggerValidation} style={{
                background:"none", border:`1px solid ${C.interactive}44`,
                color: C.interactive, padding:"3px 10px", fontSize:11, cursor:"pointer",
                fontFamily:"'IBM Plex Sans',sans-serif",
              }}>↺ Re-validate</button>
            </>
          ) : (
            <div style={{ display:"flex", alignItems:"center", gap:12 }}>
              <span style={{ fontSize:12, color:C.text03 }}>Not yet validated</span>
              <button onClick={triggerValidation} style={{
                background:"none", border:`1px solid ${C.interactive}44`,
                color: C.interactive, padding:"4px 12px", fontSize:11,
                cursor:"pointer", fontFamily:"'IBM Plex Sans',sans-serif",
              }}>✦ Run AI Validate</button>
            </div>
          )}
        </div>

        {/* ── Call Graph ── */}
        {finding.source_type === "source_code" && finding.reachable !== undefined && finding.reachable !== null && (() => {
          const chain = (() => { try { return JSON.parse(finding.call_chain || "[]"); } catch { return []; } })();
          const isReachable   = finding.reachable;
          const isModuleLevel = chain.length === 1 && chain[0] === "<module-level>";

          // For long chains: show first 2 + ellipsis + last 1
          const MAX_VISIBLE = 4;
          const truncated  = chain.length > MAX_VISIBLE + 1;
          const visibleChain = truncated
            ? [...chain.slice(0, 2), null, ...chain.slice(-1)]
            : chain;

          return (
            <div style={{ background: C.layer02, border: `1px solid ${C.border}`, padding: 12 }}>
              {sectionLabel("⬡ CALL GRAPH")}
              {isReachable ? (
                isModuleLevel ? (
                  <div style={{ display:"flex", alignItems:"flex-start", gap:8,
                    background:"#001d3322", border:`1px solid #78a9ff44`, padding:"10px 12px" }}>
                    <span style={{ color:"#78a9ff", fontSize:15 }}>⊕</span>
                    <div>
                      <div style={{ fontSize:13, color:C.text01, fontWeight:600, marginBottom:3 }}>
                        Module-level code
                      </div>
                      <div style={{ fontSize:12, color:C.text03, lineHeight:1.5 }}>
                        This usage is at module scope — executed unconditionally when the module
                        is imported. It is always reachable from any entry point that imports this file.
                      </div>
                    </div>
                  </div>
                ) : (
                  <div>
                    {/* Vertical call chain */}
                    <div style={{ display:"flex", flexDirection:"column", gap:0, marginBottom:8 }}>
                      {visibleChain.map((fn, i) => {
                        const isFirst  = i === 0;
                        const isLast   = i === visibleChain.length - 1;
                        const isElide  = fn === null;
                        const origIdx  = isElide ? -1 : (i < 2 ? i : chain.length - (visibleChain.length - i));
                        if (isElide) {
                          return (
                            <div key="elide" style={{ display:"flex", alignItems:"center", paddingLeft:10, gap:0 }}>
                              <div style={{ width:1, background:C.border, height:8, marginLeft:9 }} />
                              <div style={{ display:"flex", flexDirection:"column", alignItems:"center",
                                            marginLeft:0 }}>
                                <div style={{ width:1, background:C.border, height:6, marginLeft:9 }} />
                                <span style={{ fontSize:11, color:C.text03, marginLeft:18 }}>
                                  ··· {chain.length - 3} more steps
                                </span>
                                <div style={{ width:1, background:C.border, height:6, marginLeft:9 }} />
                              </div>
                            </div>
                          );
                        }
                        return (
                          <div key={i} style={{ display:"flex", alignItems:"stretch", gap:0 }}>
                            {/* Vertical line + circle connector */}
                            <div style={{ display:"flex", flexDirection:"column", alignItems:"center",
                                          width:20, flexShrink:0 }}>
                              {!isFirst && (
                                <div style={{ width:1, background:C.border, flex:"0 0 8px" }} />
                              )}
                              <div style={{
                                width:10, height:10, borderRadius:"50%", flexShrink:0,
                                background: isFirst ? "#78a9ff" : isLast ? "#fa4d56" : C.layer03,
                                border: `2px solid ${isFirst ? "#78a9ff" : isLast ? "#fa4d56" : C.borderStrong}`,
                              }} />
                              {!isLast && (
                                <div style={{ width:1, background:C.border, flex:"1 0 8px" }} />
                              )}
                            </div>
                            {/* Step content */}
                            <div style={{ flex:1, paddingLeft:8, paddingBottom: isLast ? 0 : 4,
                                          paddingTop: isFirst ? 0 : 4, display:"flex", alignItems:"center" }}>
                              <span style={{
                                fontSize:11, color:C.text03, width:16, flexShrink:0, textAlign:"right",
                                marginRight:6,
                              }}>{origIdx}</span>
                              <span style={{
                                fontSize:12, padding:"2px 9px",
                                background: isFirst ? "#002d9c22" : isLast ? "#da1e2822" : C.layer03,
                                color:      isFirst ? "#78a9ff"   : isLast ? "#fa4d56"   : C.text02,
                                border: `1px solid ${isFirst ? "#78a9ff44" : isLast ? "#fa4d5644" : C.border}`,
                                fontFamily:"'IBM Plex Mono',monospace",
                              }}>
                                {fn}()
                              </span>
                              {isFirst && (
                                <span style={{ fontSize:10, color:"#78a9ff", marginLeft:6,
                                               background:"#78a9ff18", border:"1px solid #78a9ff33",
                                               padding:"1px 5px" }}>entry point</span>
                              )}
                              {isLast && (
                                <span style={{ fontSize:10, color:"#fa4d56", marginLeft:6,
                                               background:"#fa4d5618", border:"1px solid #fa4d5633",
                                               padding:"1px 5px" }}>vulnerable</span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    <div style={{ fontSize:11, color:C.text03 }}>
                      Reachable from entry point · depth {finding.call_depth ?? chain.length - 1}
                    </div>
                  </div>
                )
              ) : (
                <div style={{ display:"flex", alignItems:"flex-start", gap:8,
                  background:"#2b2200", border:"1px solid #f1c21b44", padding:"10px 12px" }}>
                  <span style={{ color:"#f1c21b", fontSize:15 }}>⚠</span>
                  <div>
                    <div style={{ fontSize:13, color:C.text01, fontWeight:600, marginBottom:3 }}>
                      Not reachable from any entry point
                    </div>
                    <div style={{ fontSize:12, color:C.text03, lineHeight:1.5 }}>
                      Static analysis found no call path from <code>main()</code>, route handlers, or
                      other entry points to this function. This usage may be dead code or test-only.
                      AI analysis has flagged it as a likely false positive — review before confirming.
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })()}

        {/* ── Migration Playbook ── */}
        <div style={{ background: C.layer02, border: `1px solid ${C.border}`, padding: 12 }}>
          {sectionLabel(`📋 MIGRATION PLAYBOOK — ${finding.algorithm}`)}
          {playbookLoading && <span style={{ fontSize:12, color:C.text03 }}>Loading…</span>}
          {!playbookLoading && !playbook && (
            <span style={{ fontSize:12, color:C.text03 }}>No playbook available for this algorithm.</span>
          )}
          {playbook && (() => {
            // Pick first available language for code snippet
            const langs     = playbook.languages || {};
            const langKey   = Object.keys(langs)[0];
            const langEntry = langs[langKey];
            const snippet   = langEntry?.after || langEntry?.before;
            return (
              <>
                {playbook.quantum_risk && (
                  <div style={{ marginBottom:10 }}>
                    <div style={{ fontSize:11, color:C.text03, marginBottom:3 }}>Why vulnerable</div>
                    <div style={{ fontSize:12, color:C.text01, lineHeight:1.5 }}>{playbook.quantum_risk}</div>
                  </div>
                )}
                <div style={{ marginBottom:10 }}>
                  <div style={{ fontSize:11, color:C.text03, marginBottom:3 }}>Replace with</div>
                  <div style={{ fontSize:12, color:C.success, fontWeight:600 }}>
                    {finding.nist_replacement || playbook.nist_replacement}
                  </div>
                </div>
                {playbook.migration_effort && (
                  <div style={{ marginBottom:10 }}>
                    <div style={{ fontSize:11, color:C.text03, marginBottom:3 }}>Migration effort</div>
                    <div style={{ fontSize:12, color:C.text01, textTransform:"capitalize" }}>
                      {playbook.migration_effort}
                    </div>
                  </div>
                )}
                {playbook.steps?.length > 0 && (
                  <div style={{ marginBottom:10 }}>
                    <div style={{ fontSize:11, color:C.text03, marginBottom:4 }}>Steps</div>
                    <ol style={{ margin:0, paddingLeft:18 }}>
                      {playbook.steps.slice(0,3).map((s,i) => (
                        <li key={i} style={{ fontSize:12, color:C.text02, marginBottom:3, lineHeight:1.5 }}>{s}</li>
                      ))}
                      {playbook.steps.length > 3 && (
                        <li style={{ fontSize:11, color:C.text03, listStyle:"none" }}>
                          + {playbook.steps.length - 3} more…
                        </li>
                      )}
                    </ol>
                  </div>
                )}
                {snippet && langKey && (
                  <div style={{ marginBottom:10 }}>
                    <div style={{ fontSize:11, color:C.text03, marginBottom:4 }}>
                      Example ({langKey})
                    </div>
                    <pre style={{
                      background:"#0a0a0a", border:`1px solid ${C.border}`,
                      padding:"8px 12px", fontSize:11, color:"#42be65", margin:0,
                      fontFamily:"'IBM Plex Mono',monospace",
                      whiteSpace:"pre-wrap", overflowX:"auto", maxHeight:120,
                    }}>{snippet}</pre>
                  </div>
                )}
                <button onClick={() => onOpenPlaybook && onOpenPlaybook(finding.algorithm)}
                  style={{
                    background:"none", border:`1px solid ${C.interactive}44`,
                    color:C.interactive, padding:"4px 12px", fontSize:11,
                    cursor:"pointer", fontFamily:"'IBM Plex Sans',sans-serif",
                  }}>
                  📋 View Full Playbook →
                </button>
              </>
            );
          })()}
        </div>

        {/* ── Actions ── */}
        <div style={{ background: C.layer02, border: `1px solid ${C.border}`, padding: 12 }}>
          {sectionLabel("ACTIONS")}
          <div style={{ display:"flex", gap:8, flexWrap:"wrap", alignItems:"center" }}>
            <span style={{ fontSize:11, padding:"2px 8px",
                background:`${statusColor}18`, color:statusColor,
                border:`1px solid ${statusColor}44` }}>
              {finding.migration_status?.replace("_"," ")}
            </span>
            {["open","re_opened"].includes(finding.migration_status) && (<>
              {btn("✓ Resolve",         () => onStatusChange(finding,"manually_resolved"), C.success)}
              {btn("✗ False Positive",  () => onStatusChange(finding,"false_positive"),    C.text02, C.border)}
            </>)}
            {finding.migration_status === "false_positive" && (
              btn("↩ Re-open", () => onStatusChange(finding,"open"), C.warning)
            )}
            {["auto_resolved","manually_resolved"].includes(finding.migration_status) && (
              btn("↩ Re-open", () => onStatusChange(finding,"open"), C.warning)
            )}
          </div>
          {finding.resolution_note && (
            <p style={{ margin:"8px 0 0", fontSize:11, color:C.text03 }}>{finding.resolution_note}</p>
          )}
        </div>

      </div>
    </div>
  );
}

function ScanExplorerView() {
  const STATUS_TABS = [
    { key: "open",               label: "Open",             color: "#fa4d56" },
    { key: "re_opened",          label: "Re-opened",        color: "#ff832b" },
    { key: "false_positive",     label: "False Positive",   color: "#a8a8a8" },
    { key: "auto_resolved",      label: "Auto Resolved",    color: "#42be65" },
    { key: "manually_resolved",  label: "Manually Resolved",color: "#4589ff" },
    { key: "__archived__",       label: "Archived",         color: "#6f6f6f" },
  ];

  const [activeTab,    setActiveTab]    = useState("open");
  const [findings,     setFindings]     = useState([]);
  const [summary,      setSummary]      = useState(null);
  const [repos,        setRepos]        = useState([]);
  const [projects,     setProjects]     = useState([]);
  const [loading,      setLoading]      = useState(false);
  const [detailFinding, setDetailFinding] = useState(null);
  const [err,        setErr]        = useState(null);
  const [toast,      setToast]      = useState(null);
  const [resolveModal, setResolveModal] = useState(null);
  const [resolveNote,  setResolveNote]  = useState({ note:"", migratedTo:"" });
  const [selAlgoPlaybook, setSelAlgoPlaybook] = useState(null);
  const [filter, setFilter] = useState({ risk_level: "", quantum_status: "", repo_id: "", project_id: "", source_type: "", cve_id: "", search: "" });

  // ── Load findings for a given tab ──────────────────────────────────────────
  const load = async (tab, f) => {
    const activeFilter = f !== undefined ? f : filter;
    setLoading(true); setErr(null);
    try {
      const params = Object.fromEntries(Object.entries(activeFilter).filter(([,v]) => v));
      let fi;
      if ((tab || activeTab) === "__archived__") {
        fi = await api.getArchivedFindings(params);
      } else {
        fi = await api.getFindings({ ...params, migration_status: tab || activeTab });
      }
      const s = await api.getFindingsSummary();
      setFindings(Array.isArray(fi) ? fi : []);
      setSummary(s);
    } catch (e) { setErr(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    api.getRepos().then(r => setRepos(Array.isArray(r) ? r : [])).catch(() => {});
    api.getProjects().then(p => setProjects(Array.isArray(p) ? p : [])).catch(() => {});
    load("open", {});
  }, []);

  const switchTab = (key) => { setActiveTab(key); load(key, filter); };

  // ── Actions ────────────────────────────────────────────────────────────────
  const resolveManually = async () => {
    if (!resolveModal) return;
    try {
      await api.updateFindingStatus(resolveModal.finding.id, {
        status: "manually_resolved", resolved_by: "user",
        resolution_note: resolveNote.note,
        migrated_to:     resolveNote.migratedTo || resolveModal.finding.nist_replacement || null,
      });
      setToast({ kind: "success", title: "Marked as resolved", subtitle: resolveModal.finding.algorithm });
      setResolveModal(null); setResolveNote({ note:"", migratedTo:"" });
      load(activeTab, filter);
    } catch (e) { setToast({ kind: "error", title: "Failed", subtitle: e.message }); }
  };

  const reopen = async (finding) => {
    try {
      await api.updateFindingStatus(finding.id, { status: "open", resolved_by: "user" });
      setToast({ kind: "success", title: "Re-opened", subtitle: finding.algorithm });
      load(activeTab, filter);
    } catch (e) { setToast({ kind: "error", title: "Failed", subtitle: e.message }); }
  };

  const archive = async (finding) => {
    try {
      await api.archiveFinding(finding.id, { archived_by: "user" });
      setToast({ kind: "success", title: "Archived", subtitle: finding.algorithm });
      load(activeTab, filter);
    } catch (e) { setToast({ kind: "error", title: "Failed", subtitle: e.message }); }
  };

  const restore = async (finding) => {
    try {
      await api.restoreFinding(finding.id);
      setToast({ kind: "success", title: "Restored", subtitle: finding.algorithm });
      load(activeTab, filter);
    } catch (e) { setToast({ kind: "error", title: "Failed", subtitle: e.message }); }
  };

  const archiveAllResolved = async () => {
    try {
      const r = await api.archiveResolved({ archived_by: "user" });
      setToast({ kind: "success", title: "Archived resolved findings", subtitle: `${r.archived} findings archived` });
      load(activeTab, filter);
    } catch (e) { setToast({ kind: "error", title: "Failed", subtitle: e.message }); }
  };

  // ── Badge count for tabs ───────────────────────────────────────────────────
  const badge = (key) => {
    if (key === "__archived__") return summary?.archived_count || 0;
    return summary?.by_status?.[key] || 0;
  };

  // ── Handle status change from detail panel ────────────────────────────────
  const handleStatusChange = async (finding, newStatus) => {
    try {
      await api.updateFindingStatus(finding.id, { status: newStatus, resolved_by: "user" });
      setToast({ kind: "success", title: `Marked as ${newStatus.replace("_", " ")}`, subtitle: finding.algorithm });
      setDetailFinding(null);
      load(activeTab, filter);
    } catch (e) { setToast({ kind: "error", title: "Failed", subtitle: e.message }); }
  };

  // ── Render action buttons per row ─────────────────────────────────────────
  const rowActions = (f) => {
    const isArchived = activeTab === "__archived__";
    const isResolved = ["auto_resolved","manually_resolved"].includes(activeTab);
    const isFP       = activeTab === "false_positive";
    const btn = (label, onClick, color, title) => (
      <button onClick={e => { e.stopPropagation(); onClick(); }} title={title}
        style={{ background:"none", border:`1px solid ${color}22`, color,
          padding:"3px 9px", fontSize:11, cursor:"pointer", whiteSpace:"nowrap",
          fontFamily:"'IBM Plex Sans',sans-serif", letterSpacing:"0.2px" }}>
        {label}
      </button>
    );
    return (
      <div style={{ display:"flex", gap:4, alignItems:"center", flexWrap:"nowrap" }}>
        {!isArchived && !isResolved && !isFP && activeTab !== "manually_resolved" &&
          btn("✓ Resolve", () => { setResolveModal({ finding:f }); setResolveNote({ note:"", migratedTo:"" }); }, C.success)}
        {activeTab === "re_opened" &&
          btn("✓ Re-resolve", () => { setResolveModal({ finding:f }); setResolveNote({ note:"", migratedTo:"" }); }, C.success)}
        {(isFP || (!isArchived && isResolved)) &&
          btn("↩ Re-open", () => reopen(f), C.warning)}
        {!isArchived &&
          btn("⊘ Archive", () => archive(f), C.text03, "Soft-delete — kept for audit trail")}
        {isArchived &&
          btn("↑ Restore", () => restore(f), C.interactive)}
      </div>
    );
  };

  // Only show repo column when "All repositories" is selected
  const showRepoCol = !filter.repo_id;

  const headers = [
    { key: "algorithm",   label: "Algorithm"       },
    { key: "type",        label: "Type"             },
    ...(showRepoCol ? [{ key: "repo", label: "Repository" }] : []),
    { key: "file",        label: "File / Package"   },
    { key: "line",        label: "Line"             },
    { key: "risk",        label: "Risk"             },
    { key: "qstatus",     label: "Quantum Status"   },
    { key: "ai_conf",     label: "AI Confidence"    },
    { key: "replacement", label: "NIST Replacement" },
    { key: "actions",     label: ""                 },
  ];

  const rows = findings.map((f, i) => {
    const repoName = repos.find(r => r.id === f.repo_id)?.name;
    return {
    id: f.id || i,
    _raw: f,   // keep raw finding for row click
    _search: [f.algorithm, f.file_path, f.algo_type, f.risk_level, f.quantum_status, repoName, f.dependency_name, f.dependency_version, ...(f.cves || []).map(c => c.cve_id)].filter(Boolean).join(" "),
    algorithm:   <strong style={{ cursor: "pointer" }} onClick={() => setDetailFinding(f)}>{f.algorithm}</strong>,
    type:        f.algo_type,
    ...(showRepoCol ? { repo: repoName
      ? <span style={{ fontSize:12, color:C.interactive,
          background:C.layer02, padding:"2px 8px",
          border:`1px solid ${C.border}` }}>{repoName}</span>
      : <span style={{ color:C.text03, fontSize:12 }}>{f.repo_id?.slice(0,8)}</span>
    } : {}),
    file: f.source_type === "dependency" ? (
      <span style={{ display:"flex", flexDirection:"column", gap:2 }}>
        <span style={{ display:"flex", alignItems:"center", gap:6 }}>
          <span style={{ fontSize:10, fontWeight:700, padding:"1px 5px",
              background:"#ff832b22", color:"#ff832b",
              border:"1px solid #ff832b55", whiteSpace:"nowrap" }}>DEP</span>
          <strong style={{ fontSize:13, color:C.text01 }}>
            {f.dependency_name}
            {f.dependency_version
              ? <span style={{ color:C.text03, fontWeight:400 }}>=={f.dependency_version}</span>
              : <span style={{ color:C.text03, fontWeight:400, fontSize:11 }}> (unpinned)</span>}
          </strong>
          {f.cves?.length > 0 && (
            <span title={f.cves.map(c => c.cve_id).join(", ")} style={{ fontSize:10, fontWeight:700, padding:"1px 5px",
                background:"#fa4d5622", color:"#fa4d56",
                border:"1px solid #fa4d5655", whiteSpace:"nowrap" }}>
              ⚠ {f.cves.length} CVE{f.cves.length > 1 ? "s" : ""}
            </span>
          )}
        </span>
        <span style={{ display:"flex", alignItems:"center", gap:6 }}>
          <span style={{ fontSize:11, color:C.text03, fontFamily:"'IBM Plex Mono',monospace" }}>
            {f.file_path ? (f.file_path.split("/").length > 2 ? "…/" + f.file_path.split("/").slice(-2).join("/") : f.file_path) : ""}
          </span>
          <button onClick={e => { e.stopPropagation(); setDetailFinding(f); }}
            style={{ background:"none", border:`1px solid ${C.interactive}44`, color:C.interactive,
              padding:"1px 7px", fontSize:10, cursor:"pointer",
              fontFamily:"'IBM Plex Sans',sans-serif" }}>
            Details →
          </button>
        </span>
      </span>
    ) : (
      <span style={{ display:"flex", flexDirection:"column", gap:2 }}>
        <span style={{ display:"flex", alignItems:"center", gap:6 }}>
          <span style={{ fontSize:12, color:C.text02, fontFamily:"'IBM Plex Mono',monospace",
              overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap",
              maxWidth:220 }} title={f.file_path}>
            {f.file_path ? (f.file_path.split("/").length > 2 ? "…/" + f.file_path.split("/").slice(-2).join("/") : f.file_path) : ""}
          </span>
          <span style={{ fontSize:10, fontWeight:700, padding:"1px 5px",
              background:"#4589ff22", color:"#4589ff",
              border:"1px solid #4589ff55", whiteSpace:"nowrap" }}>SRC</span>
        </span>
        <button onClick={e => { e.stopPropagation(); setDetailFinding(f); }}
          style={{ background:"none", border:"none", padding:0,
            fontSize:10, color:C.interactive, cursor:"pointer",
            fontFamily:"'IBM Plex Sans',sans-serif", textAlign:"left" }}>
          Details →
        </button>
      </span>
    ),
    line:        f.source_type === "dependency" ? "—" : f.line_number,
    risk:        <Tag value={f.risk_level} small />,
    qstatus:     <Tag value={f.quantum_status} small />,
    ai_conf: (() => {
      const conf = f.ai_confidence;
      if (conf == null || !f.ai_validated) return <span style={{ color:C.text03, fontSize:11 }}>—</span>;
      const pct = Math.round(conf * 100);
      const color = pct >= 80 ? C.error : pct >= 50 ? C.warning : C.success;
      const bg    = pct >= 80 ? "#fa4d5618" : pct >= 50 ? "#f1c21b18" : "#42be6518";
      return (
        <span style={{ fontSize:11, padding:"2px 8px",
          background:bg, color, border:`1px solid ${color}44`,
          fontWeight:600, whiteSpace:"nowrap" }}>
          {pct}%
        </span>
      );
    })(),
    replacement: f.migrated_to
      ? <span style={{ color:C.success, fontSize:12, fontWeight:600 }}>✓ {f.migrated_to}</span>
      : f.nist_replacement
        ? <span style={{ color:C.success, fontSize:12 }}>→ {f.nist_replacement}</span>
        : <span style={{ color:C.text03 }}>—</span>,
    actions: rowActions(f),
  };});

  return (
    <div>
      {toast && <div style={{ position:"fixed", top:56, right:16, zIndex:9999, minWidth:340 }}>
        <Notification {...toast} onClose={() => setToast(null)} />
      </div>}
      {selAlgoPlaybook && <PlaybookModal algorithm={selAlgoPlaybook} onClose={() => setSelAlgoPlaybook(null)} />}
      {detailFinding && (
        <FindingDetailPanel
          finding      = {detailFinding}
          allFindings  = {findings}
          repos        = {repos}
          onClose      = {() => setDetailFinding(null)}
          onNavigate   = {(dir) => {
            const idx = findings.findIndex(f => f.id === detailFinding.id);
            const next = findings[idx + dir];
            if (next) setDetailFinding(next);
          }}
          onStatusChange  = {handleStatusChange}
          onOpenPlaybook  = {setSelAlgoPlaybook}
        />
      )}

      <PageHeader title="Scan Explorer"
        description="Browse, resolve and archive cryptographic findings across repositories"
        action={
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={async () => {
              try {
                const r = await api.validateBatch(filter.repo_id || null);
                setToast({ kind: "success", title: "AI Validation queued", subtitle: `${r.queued} finding(s) sent to Granite` });
                setTimeout(() => load(activeTab, filter), 2000);
              } catch (e) { setToast({ kind: "error", title: "AI Error", subtitle: e.message }); }
            }} style={{ ...S.btnSecondary, fontSize:12 }}>
              ✦ Validate All with AI
            </button>
            <button onClick={archiveAllResolved} style={{ ...S.btnSecondary, fontSize:12 }}>
              ⊘ Archive All Resolved
            </button>
          </div>
        }
      />

      {err && <Notification kind="error" title="Error" subtitle={err} onClose={() => setErr(null)} />}

      {/* ── Risk stat tiles ── */}
      {summary && (
        <div style={{ display:"flex", gap:2, flexWrap:"wrap", marginBottom:16 }}>
          {Object.entries(summary.by_risk || {}).map(([k,v]) => (
            <StatTile key={k} label={k} value={v} accent={C.risk[k]} />
          ))}
          <StatTile label="Total" value={summary.total} accent={C.interactive} />
        </div>
      )}

      {/* ── Filters ── */}
      <div style={{ display:"flex", gap:8, marginBottom:16, flexWrap:"wrap", alignItems:"flex-end" }}>

        <div style={{ minWidth: 180 }}>
          <label style={S.label}>Project</label>
          <select style={{ ...S.select, minWidth: 180 }} value={filter.project_id}
            onChange={e => setFilter(f => ({ ...f, project_id: e.target.value, repo_id: "" }))}>
            <option value="">All projects</option>
            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>

        <div style={{ minWidth: 180 }}>
          <label style={S.label}>Repository</label>
          <select style={{ ...S.select, minWidth: 180 }} value={filter.repo_id}
            onChange={e => setFilter(f => ({ ...f, repo_id: e.target.value }))}>
            <option value="">All repositories</option>
            {repos
              .filter(r => !filter.project_id || r.project_id === filter.project_id)
              .map(r => (
                <option key={r.id} value={r.id}>
                  {r.name}{r.risk_level && r.risk_level !== "UNKNOWN" ? ` (${r.risk_level})` : ""}
                </option>
              ))}
          </select>
        </div>

        <div>
          <label style={S.label}>Risk Level</label>
          <select style={S.select} value={filter.risk_level}
            onChange={e => setFilter(f => ({ ...f, risk_level: e.target.value }))}>
            <option value="">All risk levels</option>
            {["CRITICAL","HIGH","MEDIUM","LOW"].map(o => <option key={o} value={o}>{o}</option>)}
          </select>
        </div>

        <div>
          <label style={S.label}>Quantum Status</label>
          <select style={S.select} value={filter.quantum_status}
            onChange={e => setFilter(f => ({ ...f, quantum_status: e.target.value }))}>
            <option value="">All statuses</option>
            {["BROKEN","VULNERABLE","WEAK","MONITOR","SAFE"].map(o => <option key={o} value={o}>{o}</option>)}
          </select>
        </div>

        <div>
          <label style={S.label}>Source</label>
          <select style={S.select} value={filter.source_type}
            onChange={e => setFilter(f => ({ ...f, source_type: e.target.value }))}>
            <option value="">All sources</option>
            <option value="source_code">Source Code</option>
            <option value="dependency">Dependency</option>
          </select>
        </div>

        <div>
          <label style={S.label}>CVE ID</label>
          <input style={{ ...S.input, width: 180 }} placeholder="e.g. CVE-2022-29217"
            value={filter.cve_id}
            onChange={e => setFilter(f => ({ ...f, cve_id: e.target.value }))} />
        </div>

        <button onClick={() => load(activeTab, filter)} style={S.btnPrimary}>Apply</button>
        <button onClick={() => {
          const f = { risk_level:"", quantum_status:"", repo_id:"", project_id:"", source_type:"", cve_id:"", search:"" }; // keep search in state for DataTable internal search
          setFilter(f); load(activeTab, f);
        }} style={S.btnSecondary}>Reset</button>
      </div>

      {/* Active project/repo banner */}
      {(filter.project_id || filter.repo_id) && (() => {
        const proj = projects.find(p => p.id === filter.project_id);
        const repo = repos.find(r => r.id === filter.repo_id);
        return (
          <div style={{ background:C.layer02, border:`1px solid ${C.border}`,
            borderLeft:`3px solid ${C.interactive}`,
            padding:"8px 16px", marginBottom:12, display:"flex",
            justifyContent:"space-between", alignItems:"center", fontSize:13 }}>
            <span>
              {proj && <><span style={{ color:C.text02 }}>Project: </span><strong style={{ color:C.text01 }}>{proj.name}</strong></>}
              {proj && repo && <span style={{ color:C.text03, margin:"0 8px" }}>/</span>}
              {repo && <><span style={{ color:C.text02 }}>Repo: </span><strong style={{ color:C.text01 }}>{repo.name}</strong><span style={{ color:C.text03, marginLeft:8, fontSize:12 }}>{repo.url}</span></>}
            </span>
            <button onClick={() => {
              const f = { ...filter, project_id:"", repo_id:"" };
              setFilter(f); load(activeTab, f);
            }} style={{ background:"none", border:"none", color:C.text03,
              cursor:"pointer", fontSize:18, lineHeight:1, padding:"0 4px" }}>×</button>
          </div>
        );
      })()}

      {/* ── Status tabs ── */}
      <div style={{ display:"flex", borderBottom:`1px solid ${C.border}`, marginBottom:0 }}>
        {STATUS_TABS.map(tab => {
          const count = badge(tab.key);
          const isActive = activeTab === tab.key;
          return (
            <button key={tab.key} onClick={() => switchTab(tab.key)} style={{
              padding:"10px 20px", background:"none", border:"none",
              borderBottom: isActive ? `3px solid ${tab.color}` : "3px solid transparent",
              color: isActive ? C.text01 : C.text02,
              cursor:"pointer", fontSize:13, fontFamily:"'IBM Plex Sans',sans-serif",
              display:"flex", alignItems:"center", gap:8,
              transition:"color 0.1s",
            }}>
              {tab.label}
              {count > 0 && (
                <span style={{
                  background: tab.key === "re_opened" ? C.warning :
                              tab.key === "open"      ? C.error   : C.layer02,
                  color: tab.key === "re_opened" ? "#000" :
                         tab.key === "open"      ? "#fff" : C.text02,
                  borderRadius:10, fontSize:11, fontWeight:600,
                  padding:"1px 7px", minWidth:20, textAlign:"center",
                }}>
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── Re-opened warning ── */}
      {activeTab === "re_opened" && findings.length > 0 && (
        <div style={{ background:"#2d1a00", borderBottom:`1px solid ${C.warning}`,
          padding:"10px 16px", fontSize:13, color:C.warning, display:"flex", alignItems:"center", gap:8 }}>
          ⚠ These findings were manually resolved but re-detected in a later scan. Please review and re-resolve or accept.
        </div>
      )}

      {/* ── Archived info banner ── */}
      {activeTab === "__archived__" && (
        <div style={{ background:C.layer02, borderBottom:`1px solid ${C.border}`,
          padding:"10px 16px", fontSize:13, color:C.text02, display:"flex", alignItems:"center", gap:8 }}>
          ⓘ Archived findings are kept for audit purposes. Use Restore to bring a finding back to active tracking.
        </div>
      )}

      {loading ? <Loader /> : (
        <DataTable headers={headers} rows={rows}
          emptyText={
            activeTab === "__archived__" ? "No archived findings." :
            activeTab === "open"         ? "No open findings. Run a scan to detect issues." :
            `No ${activeTab.replace("_", " ")} findings.`
          }
        />
      )}

      {findings.length > 0 && (
        <p style={{ fontSize:12, color:C.text03, marginTop:8, textAlign:"right" }}>
          Showing {findings.length} findings
        </p>
      )}

      {/* ── Resolve modal ── */}
      {resolveModal && (
        <Modal
          open={true}
          title={`Resolve: ${resolveModal.finding.algorithm}`}
          onSubmit={resolveManually}
          onClose={() => setResolveModal(null)}
          submitLabel="Mark as Resolved"
        >
          <p style={{ color:C.text02, fontSize:13, marginBottom:12 }}>
            <strong style={{ color:C.text01 }}>{resolveModal.finding.algorithm}</strong>
            <span style={{ color:C.text03 }}> in </span>
            <span style={{ fontFamily:"'IBM Plex Mono',monospace", fontSize:12 }}>
              {resolveModal.finding.file_path}:{resolveModal.finding.line_number}
            </span>
          </p>

          <label style={S.label}>Migrated to (optional)</label>
          <input
            value={resolveNote.migratedTo || resolveModal.finding.nist_replacement || ""}
            onChange={e => setResolveNote(n => ({ ...n, migratedTo: e.target.value }))}
            placeholder={resolveModal.finding.nist_replacement || "e.g. ML-KEM-768 (FIPS 203)"}
            style={{ ...S.input, marginBottom:12, width:"100%", boxSizing:"border-box" }}
          />

          <label style={S.label}>Resolution note (optional)</label>
          <textarea
            value={resolveNote.note || ""}
            onChange={e => setResolveNote(n => ({ ...n, note: e.target.value }))}
            placeholder="e.g. Replaced with ML-KEM-768 in PR #142"
            rows={3}
            style={{ ...S.input, resize:"vertical", height:"auto", padding:"8px 12px",
              width:"100%", boxSizing:"border-box", marginBottom:8 }}
          />
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
            <p style={{ fontSize:12, color:C.text03, margin:0 }}>
              ⓘ Re-detected in a future scan → marked Re-opened for review.
            </p>
            <button onClick={() => setSelAlgoPlaybook(resolveModal.finding.algorithm)}
              style={{ ...S.btnGhost, fontSize:12, color:C.interactive }}>
              📋 View Playbook
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function CBOMView() {
  const [entries,      setEntries]      = useState([]);
  const [loading,      setLoading]      = useState(true);
  const [filter,       setFilter]       = useState("ALL");
  const [projects,     setProjects]     = useState([]);
  const [projectId,    setProjectId]    = useState("");
  const [blastAlgo,    setBlastAlgo]    = useState(null); // algorithm for blast radius modal

  useEffect(() => {
    api.getProjects().then(p => setProjects(Array.isArray(p) ? p : [])).catch(() => {});
  }, []);

  useEffect(() => {
    setLoading(true);
    const url = `/api/cbom/${projectId ? `?project_id=${projectId}` : ""}`;
    req("GET", url).then(d => { setEntries(Array.isArray(d) ? d : []); setLoading(false); }).catch(() => setLoading(false));
  }, [projectId]);

  const exportCDX = async () => {
    const url = `/api/cbom/export/cyclonedx${projectId ? `?project_id=${projectId}` : ""}`;
    const res  = await req("GET", url);
    const a = document.createElement("a");
    const projName = projects.find(p => p.id === projectId)?.name?.toLowerCase().replace(/ /g,"-") || "";
    a.href = URL.createObjectURL(new Blob([JSON.stringify(res, null, 2)], { type: "application/json" }));
    a.download = `cbom${projName ? `-${projName}` : ""}-cyclonedx.json`; a.click();
  };

  const exportCSV = async () => {
    const url = `/api/cbom/export/csv${projectId ? `?project_id=${projectId}` : ""}`;
    const res = await fetch(url, { credentials: "include" });
    const blob = await res.blob();
    const projName = projects.find(p => p.id === projectId)?.name?.toLowerCase().replace(/ /g,"-") || "";
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `cbom${projName ? `-${projName}` : ""}-${new Date().toISOString().slice(0,10)}.csv`; a.click();
  };

  const filtered = filter === "ALL" ? entries : entries.filter(e => e.quantum_status === filter);
  const headers = [
    { key: "algorithm",   label: "Algorithm" },
    { key: "type",        label: "Type" },
    { key: "qstatus",     label: "Quantum Status" },
    { key: "replacement", label: "NIST Replacement" },
    { key: "priority",    label: "Priority" },
    { key: "repos",       label: "Repos" },
    { key: "usages",      label: "Usages" },
    { key: "blast",       label: "" },
  ];
  const rows = filtered.map(e => ({
    id: e.id || e.algorithm,
    algorithm: <strong>{e.algorithm}</strong>,
    type: e.algo_type,
    qstatus: <Tag value={e.quantum_status} small />,
    replacement: e.nist_replacement && e.nist_replacement !== "—"
      ? <span style={{ color: C.success, fontSize: 12 }}>{e.nist_replacement}</span>
      : <span style={{ color: C.text03 }}>—</span>,
    priority: <Tag value={`P${e.priority}`} small />,
    repos: e.affected_repos,
    usages: (
      <div>
        <span style={{ fontSize:13, color:C.text01, fontWeight:600 }}>{e.total_usages}</span>
        {(e.code_usages > 0 || e.secret_usages > 0) && (
          <div style={{ display:"flex", gap:6, marginTop:3 }}>
            {e.code_usages > 0 && (
              <span style={{ fontSize:10, color:C.interactive,
                background:C.interactive+"22", border:`1px solid ${C.interactive}33`,
                padding:"1px 6px" }}>
                ◎ {e.code_usages} code
              </span>
            )}
            {e.secret_usages > 0 && (
              <span style={{ fontSize:10, color:"#ff832b",
                background:"#ff832b22", border:"1px solid #ff832b33",
                padding:"1px 6px" }}>
                🔑 {e.secret_usages} key/cert
              </span>
            )}
          </div>
        )}
      </div>
    ),
    blast: (
      <button onClick={() => setBlastAlgo(e.algorithm)}
        style={{ ...S.btnSecondary, fontSize:11, padding:"2px 10px", height:26 }}
        title="View blast radius">
        🎯 Blast
      </button>
    ),
  }));

  return (
    <div>
      {blastAlgo && (
        <BlastRadiusModal
          algorithm={blastAlgo}
          projectId={projectId || null}
          onClose={() => setBlastAlgo(null)}
        />
      )}
      <PageHeader title="CBOM" description="Cryptography Bill of Materials · NIST SP 800-235 · CycloneDX 1.5"
        action={
          <div style={{ display: "flex", gap: 8, alignItems: "flex-end" }}>
            <select value={projectId} onChange={e => setProjectId(e.target.value)}
              style={{ ...S.select, minWidth:160 }}>
              <option value="">All projects</option>
              {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            <button onClick={exportCSV} style={S.btnSecondary}>⬇ Export CSV</button>
            <button onClick={exportCDX} style={S.btnSecondary}>⬇ Export CycloneDX</button>
          </div>
        } />
      <div style={{ display: "flex", gap: 2, marginBottom: 16, flexWrap: "wrap" }}>
        {["ALL","BROKEN","VULNERABLE","WEAK","MONITOR","SAFE"].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            style={filter === f ? { ...S.btnPrimary, height: 32, padding: "0 12px", fontSize: 12 } : { ...S.btnSecondary, height: 32, padding: "0 12px", fontSize: 12 }}>
            {f}
          </button>
        ))}
      </div>
      {loading ? <Loader /> : <DataTable headers={headers} rows={rows} emptyText="No CBOM entries yet. Run a scan to populate." />}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 2, marginTop: 16 }}>
        {[
          { std: "FIPS 203", algo: "ML-KEM",  color: C.interactive, desc: "Key Encapsulation — replaces RSA/ECDH" },
          { std: "FIPS 204", algo: "ML-DSA",  color: "#a56eff",     desc: "Digital Signatures — replaces RSA-sign/ECDSA" },
          { std: "FIPS 205", algo: "SLH-DSA", color: "#3ddbd9",     desc: "Stateless Hash-Based Signatures" },
        ].map(s => (
          <div key={s.std} style={{ ...S.tile, borderTop: `3px solid ${s.color}` }}>
            <Tag value={s.std} /><h4 style={{ margin: "8px 0 4px", fontSize: 16, fontWeight: 600, color: C.text01 }}>{s.algo}</h4>
            <p style={{ margin: 0, fontSize: 13, color: C.text02 }}>{s.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Agility helpers ──────────────────────────────────────────────────────────
const MATURITY = [
  { l:"L1", t:"Hardcoded",    d:"Algorithm baked in. No migration path.",            c:"#fa4d56", min:1, max:1 },
  { l:"L2", t:"Configurable", d:"Config-driven, restart needed to change algorithm.", c:"#ff832b", min:2, max:2 },
  { l:"L3", t:"Hot-Swap",     d:"Registry pattern. Swap algorithm without restart.",  c:"#f1c21b", min:3, max:3 },
  { l:"L4", t:"Hybrid",       d:"Classical + PQC running simultaneously.",           c:"#4589ff", min:4, max:4 },
  { l:"L5", t:"Fully Agile",  d:"Per-request algorithm negotiation.",                c:"#42be65", min:5, max:5 },
];

function AgilityBadge({ level, label, small }) {
  const m = MATURITY.find(x => x.min === level) || MATURITY[0];
  return (
    <span style={{
      display:"inline-flex", alignItems:"center", gap:6,
      background: m.c + "22", border:`1px solid ${m.c}55`,
      color: m.c, padding: small ? "1px 8px" : "3px 12px",
      fontSize: small ? 11 : 13, fontWeight:600, letterSpacing:"0.3px",
    }}>
      {m.l} — {label || m.t}
    </span>
  );
}

// ─── Playbook Modal ────────────────────────────────────────────────────────────
function PlaybookModal({ algorithm, nistReplacement, onClose }) {
  const [playbook,  setPlaybook]  = useState(null);
  const [lang,      setLang]      = useState(null);
  const [langData,  setLangData]  = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [err,       setErr]       = useState(null);

  useEffect(() => {
    api.getPlaybook(algorithm)
      .then(pb => { setPlaybook(pb); setLang(Object.keys(pb.languages)[0]); })
      .catch(e  => setErr(e.message))
      .finally(()=> setLoading(false));
  }, [algorithm]);

  useEffect(() => {
    if (!playbook || !lang) return;
    setLangData(playbook.languages[lang] || null);
  }, [playbook, lang]);

  const effortColor = { low:"#42be65", medium:"#f1c21b", high:"#ff832b" };

  return (
    <div style={{ position:"fixed", inset:0, zIndex:10000, display:"flex", alignItems:"center", justifyContent:"center" }}>
      <div onClick={onClose} style={{ position:"absolute", inset:0, background:"rgba(0,0,0,0.8)" }} />
      <div style={{ position:"relative", background:C.layer01, border:`1px solid ${C.border}`,
        width:"90vw", maxWidth:900, maxHeight:"88vh", overflow:"hidden",
        display:"flex", flexDirection:"column", zIndex:1 }}>

        {/* Header */}
        <div style={{ padding:"16px 20px", borderBottom:`1px solid ${C.border}`,
          display:"flex", justifyContent:"space-between", alignItems:"flex-start", flexShrink:0 }}>
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
              <strong style={{ fontSize:16, color:C.text01 }}>📋 Remediation Playbook</strong>
              <Tag value={algorithm} />
              {playbook && (
                <span style={{ fontSize:11, color: effortColor[playbook.migration_effort],
                  background: effortColor[playbook.migration_effort]+"22",
                  border:`1px solid ${effortColor[playbook.migration_effort]}44`,
                  padding:"1px 8px" }}>
                  {playbook.migration_effort?.toUpperCase()} EFFORT
                </span>
              )}
            </div>
            {playbook && (
              <div style={{ fontSize:12, color:C.text02 }}>
                Replace with: <span style={{ color:C.success }}>{playbook.nist_replacement}</span>
              </div>
            )}
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none",
            color:C.text02, cursor:"pointer", fontSize:22, lineHeight:1 }}>×</button>
        </div>

        {loading && <div style={{ padding:40, textAlign:"center", color:C.text02 }}>Loading playbook…</div>}
        {err    && <div style={{ padding:20 }}><Notification kind="error" title="No playbook" subtitle={err} /></div>}

        {playbook && (
          <div style={{ display:"flex", flex:1, overflow:"hidden" }}>
            {/* Left panel — steps + quantum risk */}
            <div style={{ width:280, borderRight:`1px solid ${C.border}`, padding:20,
              overflowY:"auto", flexShrink:0, background:C.bg }}>
              <div style={{ fontSize:11, fontWeight:600, color:C.text03,
                letterSpacing:"0.8px", marginBottom:12 }}>QUANTUM RISK</div>
              <div style={{ fontSize:13, color:C.warning, background:C.warning+"11",
                border:`1px solid ${C.warning}33`, padding:"10px 12px", marginBottom:20,
                lineHeight:1.5 }}>{playbook.quantum_risk}</div>

              <div style={{ fontSize:11, fontWeight:600, color:C.text03,
                letterSpacing:"0.8px", marginBottom:12 }}>MIGRATION STEPS</div>
              {playbook.steps.map((step, i) => (
                <div key={i} style={{ display:"flex", gap:10, marginBottom:12, alignItems:"flex-start" }}>
                  <span style={{ background:C.interactive, color:"#fff", borderRadius:"50%",
                    width:20, height:20, display:"flex", alignItems:"center", justifyContent:"center",
                    fontSize:11, fontWeight:600, flexShrink:0, marginTop:1 }}>{i+1}</span>
                  <span style={{ fontSize:13, color:C.text02, lineHeight:1.5 }}>{step}</span>
                </div>
              ))}

              <div style={{ fontSize:11, fontWeight:600, color:C.text03,
                letterSpacing:"0.8px", marginBottom:10, marginTop:20 }}>LANGUAGE</div>
              {Object.keys(playbook.languages).map(l => (
                <button key={l} onClick={() => setLang(l)} style={{
                  display:"block", width:"100%", textAlign:"left",
                  padding:"8px 12px", marginBottom:4, cursor:"pointer",
                  background: lang===l ? C.interactive+"33" : "none",
                  border: lang===l ? `1px solid ${C.interactive}` : `1px solid ${C.border}`,
                  color: lang===l ? C.interactive : C.text02, fontSize:13,
                  fontFamily:"'IBM Plex Sans',sans-serif",
                }}>{l}</button>
              ))}

              {langData && (
                <div style={{ marginTop:16, padding:"10px 12px", background:C.layer02,
                  border:`1px solid ${C.border}`, fontSize:12 }}>
                  <div style={{ color:C.text03, marginBottom:4 }}>Library</div>
                  <div style={{ color:C.success, fontFamily:"'IBM Plex Mono',monospace",
                    marginBottom:8 }}>{langData.library}</div>
                  <div style={{ color:C.text03, marginBottom:4 }}>Install</div>
                  <div style={{ color:C.text01, fontFamily:"'IBM Plex Mono',monospace",
                    fontSize:11, wordBreak:"break-all" }}>{langData.install}</div>
                </div>
              )}
            </div>

            {/* Right panel — before/after code */}
            {langData && (
              <div style={{ flex:1, overflow:"auto", display:"flex", flexDirection:"column" }}>
                <div style={{ flex:1, borderBottom:`1px solid ${C.border}` }}>
                  <div style={{ padding:"8px 16px", background:"#2d0709",
                    borderBottom:`1px solid #fa4d5633`, display:"flex",
                    alignItems:"center", gap:8 }}>
                    <span style={{ color:"#fa4d56", fontSize:12, fontWeight:600 }}>✕ BEFORE</span>
                    <span style={{ color:C.text03, fontSize:11 }}>{algorithm} — quantum vulnerable</span>
                  </div>
                  <pre style={{ margin:0, padding:"16px 20px", fontSize:12.5, lineHeight:1.7,
                    color:"#bebebe", fontFamily:"'IBM Plex Mono',monospace",
                    background:"#0d0d0d", overflowX:"auto", whiteSpace:"pre-wrap" }}>
                    {langData.before}
                  </pre>
                </div>
                <div style={{ flex:1 }}>
                  <div style={{ padding:"8px 16px", background:"#071e0a",
                    borderBottom:`1px solid #42be6533`, display:"flex",
                    alignItems:"center", gap:8 }}>
                    <span style={{ color:"#42be65", fontSize:12, fontWeight:600 }}>✓ AFTER</span>
                    <span style={{ color:C.text03, fontSize:11 }}>{playbook.nist_replacement}</span>
                  </div>
                  <pre style={{ margin:0, padding:"16px 20px", fontSize:12.5, lineHeight:1.7,
                    color:"#bebebe", fontFamily:"'IBM Plex Mono',monospace",
                    background:"#0a0a0a", overflowX:"auto", whiteSpace:"pre-wrap" }}>
                    {langData.after}
                  </pre>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Agility View ─────────────────────────────────────────────────────────────
function AgilityView() {
  const [repos,      setRepos]      = useState([]);
  const [playbooks,  setPlaybooks]  = useState([]);
  const [selRepo,    setSelRepo]    = useState(null);   // selected repo for detail
  const [selAlgo,    setSelAlgo]    = useState(null);   // playbook to open
  const [loading,    setLoading]    = useState(true);
  const [activeTab,  setActiveTab]  = useState("overview"); // overview | playbooks | patterns

  useEffect(() => {
    Promise.all([api.getRepos(), api.getPlaybooks()])
      .then(([r, p]) => { setRepos(r); setPlaybooks(p); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const scanned  = repos.filter(r => r.agility_level);
  const avgLevel = scanned.length
    ? Math.round(scanned.reduce((a, r) => a + r.agility_level, 0) / scanned.length)
    : null;
  const hybridCount = repos.filter(r => r.has_hybrid).length;

  const TABS = [
    { id:"overview",  label:"📊 Portfolio Overview" },
    { id:"playbooks", label:"📋 Remediation Playbooks" },
    { id:"patterns",  label:"⚙ Agility Patterns" },
  ];

  return (
    <div>
      {selAlgo && <PlaybookModal algorithm={selAlgo} onClose={() => setSelAlgo(null)} />}

      <PageHeader title="Crypto Agility" description="Per-repo agility scoring, remediation playbooks and migration patterns" />

      {/* ── Summary stat tiles ── */}
      <div style={{ display:"flex", gap:2, flexWrap:"wrap", marginBottom:20 }}>
        <StatTile label="Repos Scored"   value={scanned.length}  accent={C.interactive} />
        <StatTile label="Avg Maturity"   value={avgLevel ? `L${avgLevel}` : "—"} accent={
          avgLevel >= 4 ? C.success : avgLevel >= 3 ? C.warning : C.error} />
        <StatTile label="Hybrid Detected" value={hybridCount}    accent="#4589ff" />
        <StatTile label="Playbooks"       value={playbooks.length} accent="#a56eff" />
        <StatTile label="Need Urgent Migration"
          value={repos.filter(r => r.agility_level === 1).length} accent={C.error} />
      </div>

      {/* ── Tabs ── */}
      <div style={{ display:"flex", borderBottom:`1px solid ${C.border}`, marginBottom:0 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
            padding:"10px 20px", background:"none", border:"none",
            borderBottom: activeTab===t.id ? `3px solid ${C.interactive}` : "3px solid transparent",
            color: activeTab===t.id ? C.text01 : C.text02,
            cursor:"pointer", fontSize:13, fontFamily:"'IBM Plex Sans',sans-serif",
          }}>{t.label}</button>
        ))}
      </div>

      {/* ══ TAB: Portfolio Overview ══════════════════════════════════════════ */}
      {activeTab === "overview" && (
        <div style={{ paddingTop:16 }}>
          {loading && <div style={{ color:C.text02, padding:20 }}>Loading…</div>}
          {!loading && repos.length === 0 && (
            <div style={{ ...S.tile, textAlign:"center", padding:48, color:C.text03 }}>
              No repositories yet. Add repos and run scans to see agility scores.
            </div>
          )}

          {/* Maturity model legend */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:2, marginBottom:16 }}>
            {MATURITY.map(m => (
              <div key={m.l} style={{ ...S.tile, borderTop:`3px solid ${m.c}`, textAlign:"center" }}>
                <div style={{ fontSize:22, fontWeight:300, color:m.c }}>{m.l}</div>
                <div style={{ fontSize:13, fontWeight:600, color:C.text01, marginTop:4 }}>{m.t}</div>
                <div style={{ fontSize:11, color:C.text02, marginTop:4, lineHeight:1.4 }}>{m.d}</div>
              </div>
            ))}
          </div>

          {/* Repo agility cards */}
          <h3 style={{ fontSize:14, fontWeight:600, color:C.text01, margin:"20px 0 12px",
            letterSpacing:"0.32px", textTransform:"uppercase" }}>Repository Scores</h3>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(340px, 1fr))", gap:2 }}>
            {repos.map(repo => {
              const m = MATURITY.find(x => x.min === repo.agility_level);
              const notScanned = !repo.agility_level;
              return (
                <div key={repo.id} style={{ ...S.tile,
                  borderLeft:`3px solid ${notScanned ? C.border : (m?.c || C.border)}`,
                  cursor: selRepo?.id === repo.id ? "default" : "pointer" }}
                  onClick={() => setSelRepo(selRepo?.id === repo.id ? null : repo)}>

                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
                    <div>
                      <div style={{ fontSize:14, fontWeight:600, color:C.text01 }}>{repo.name}</div>
                      <div style={{ fontSize:11, color:C.text03, marginTop:2 }}>{repo.provider} · {repo.branch}</div>
                    </div>
                    <div style={{ textAlign:"right" }}>
                      {notScanned
                        ? <span style={{ fontSize:11, color:C.text03 }}>Not scanned</span>
                        : <AgilityBadge level={repo.agility_level} label={repo.agility_label} small />
                      }
                      {repo.has_hybrid && (
                        <div style={{ fontSize:10, color:"#4589ff", marginTop:4 }}>⬡ Hybrid PQC detected</div>
                      )}
                    </div>
                  </div>

                  {/* Risk + agility bar */}
                  {repo.agility_level && (
                    <div style={{ marginTop:12 }}>
                      <div style={{ display:"flex", justifyContent:"space-between",
                        fontSize:11, color:C.text03, marginBottom:4 }}>
                        <span>Agility score: {repo.agility_score ?? 0}</span>
                        <span>Risk: <span style={{ color:C.risk[repo.risk_level] }}>{repo.risk_level}</span></span>
                      </div>
                      <div style={{ height:4, background:C.layer03, position:"relative" }}>
                        <div style={{ position:"absolute", left:0, top:0, height:"100%",
                          width:`${Math.min(100, ((repo.agility_level - 1) / 4) * 100)}%`,
                          background: m?.c || C.interactive, transition:"width 0.5s ease" }} />
                      </div>
                    </div>
                  )}

                  {/* Expanded signals */}
                  {selRepo?.id === repo.id && repo.agility_signals && (
                    <div style={{ marginTop:12, borderTop:`1px solid ${C.border}`, paddingTop:12 }}>
                      <div style={{ fontSize:11, color:C.text03, marginBottom:8,
                        letterSpacing:"0.8px" }}>DETECTED SIGNALS</div>
                      {(() => {
                        try {
                          const sigs = JSON.parse(repo.agility_signals || "[]");
                          if (!sigs.length) return (
                            <div style={{ fontSize:12, color:C.text03 }}>No agility signals detected.</div>
                          );
                          return sigs.slice(0,8).map((s, i) => (
                            <div key={i} style={{ display:"flex", gap:8, marginBottom:6,
                              alignItems:"flex-start" }}>
                              <span style={{ color: s.bump > 0 ? C.success : C.error,
                                fontSize:12, flexShrink:0, marginTop:1 }}>
                                {s.bump > 0 ? `+${s.bump}` : s.bump}
                              </span>
                              <div>
                                <div style={{ fontSize:12, color:C.text01 }}>{s.description}</div>
                                <div style={{ fontSize:11, color:C.text03,
                                  fontFamily:"'IBM Plex Mono',monospace" }}>
                                  {s.file}:{s.line}
                                </div>
                              </div>
                            </div>
                          ));
                        } catch { return null; }
                      })()}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ══ TAB: Remediation Playbooks ═══════════════════════════════════════ */}
      {activeTab === "playbooks" && (
        <div style={{ paddingTop:16 }}>
          <p style={{ fontSize:13, color:C.text02, marginBottom:16 }}>
            Each playbook provides language-specific before/after code, library recommendations and step-by-step migration instructions.
          </p>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(300px, 1fr))", gap:2 }}>
            {playbooks.map(pb => {
              const effortColor = { low:C.success, medium:C.warning, high:C.error };
              const sevColor    = C.risk[pb.severity] || C.text02;
              return (
                <div key={pb.algorithm} style={{ ...S.tile,
                  borderTop:`3px solid ${sevColor}`, cursor:"pointer",
                  transition:"background 0.1s" }}
                  onClick={() => setSelAlgo(pb.algorithm)}>
                  <div style={{ display:"flex", justifyContent:"space-between", marginBottom:8 }}>
                    <Tag value={pb.algorithm} />
                    <span style={{ fontSize:11, color: effortColor[pb.migration_effort] || C.text03,
                      background:(effortColor[pb.migration_effort]||C.text03)+"22",
                      border:`1px solid ${(effortColor[pb.migration_effort]||C.text03)}44`,
                      padding:"1px 8px" }}>
                      {pb.migration_effort?.toUpperCase()}
                    </span>
                  </div>
                  <div style={{ fontSize:13, color:C.success, marginBottom:8 }}>→ {pb.nist_replacement}</div>
                  <div style={{ display:"flex", gap:4, flexWrap:"wrap" }}>
                    {(pb.languages || []).map(l => (
                      <span key={l} style={{ fontSize:10, color:C.text03,
                        background:C.layer02, border:`1px solid ${C.border}`,
                        padding:"1px 6px" }}>{l}</span>
                    ))}
                  </div>
                  <div style={{ marginTop:12, fontSize:12, color:C.interactive }}>
                    View playbook →
                  </div>
                </div>
              );
            })}
            {playbooks.length === 0 && !loading && (
              <div style={{ color:C.text03, fontSize:13, padding:20 }}>No playbooks loaded.</div>
            )}
          </div>
        </div>
      )}

      {/* ══ TAB: Agility Patterns ════════════════════════════════════════════ */}
      {activeTab === "patterns" && <AgilityPatternsPanel />}
    </div>
  );
}

// ─── Agility Patterns Panel (extracted from old AgilityView) ─────────────────
const PATTERNS = [
  { name:"Crypto Provider Interface", tags:["Pattern","Interface"], lang:"typescript",
    desc:"Abstract all crypto operations behind a unified interface. Swap algorithms without changing business logic.",
    code:`interface CryptoProvider {
  sign(data: Uint8Array, key: PrivateKey): Promise<Signature>
  verify(data: Uint8Array, sig: Signature, key: PublicKey): Promise<boolean>
  encapsulate(pk: PublicKey): Promise<[Ciphertext, SharedSecret]>
  decapsulate(ct: Ciphertext, sk: PrivateKey): Promise<SharedSecret>
}
const registry = new CryptoRegistry()
registry.register("ML-DSA-65",  new MLDSAProvider())   // FIPS 204
registry.register("ML-KEM-768", new MLKEMProvider())   // FIPS 203
const provider = registry.get(config.signatureAlgorithm)` },
  { name:"Hybrid Key Exchange", tags:["Hybrid","TLS"], lang:"go",
    desc:"Run classical + PQC in parallel. Security holds if EITHER is unbroken — ideal for 2025–2027 transition.",
    code:`type HybridKEM struct {
    Classical KEM  // X25519
    PQC       KEM  // ML-KEM-768 (FIPS 203)
}
func (h *HybridKEM) Encapsulate(pk PublicKey) (Ciphertext, []byte) {
    ct1, ss1 := h.Classical.Encapsulate(pk.Classical)
    ct2, ss2 := h.PQC.Encapsulate(pk.PQC)
    return HybridCiphertext{ct1, ct2}, hkdf.Extract(sha256.New, ss1, ss2)
}` },
  { name:"Config-Driven Migration", tags:["Config","Feature Flag"], lang:"yaml",
    desc:"Feature-flag each migration. Per-environment rollout with instant rollback.",
    code:`signature:
  algorithm: ML-DSA-65        # NIST FIPS 204
  fallback:  RS256
  mode: hybrid                # hybrid | pqc_only | classical
  rollout_pct: 25
environments:
  production:  { mode: hybrid,   rollout_pct: 10  }
  staging:     { mode: pqc_only, rollout_pct: 100 }` },
  { name:"Algorithm Negotiation", tags:["API","JWT"], lang:"json",
    desc:"Embed algorithm metadata in tokens and wire formats for graceful migration.",
    code:`{
  "alg": "ML-DSA-65",
  "alg_fallback": "RS256",
  "alg_version": "2025-03",
  "kid": "pqc-signing-key-v2"
}` },
];

function AgilityPatternsPanel() {
  const [active, setActive] = useState(0);
  const p = PATTERNS[active];
  return (
    <div style={{ paddingTop:16 }}>
      <div style={{ display:"flex", borderBottom:`1px solid ${C.border}`, marginBottom:0 }}>
        {PATTERNS.map((pat, i) => (
          <button key={i} onClick={() => setActive(i)} style={{
            background:"none", border:"none",
            borderBottom: active===i ? `3px solid ${C.interactive}` : "3px solid transparent",
            color: active===i ? C.interactive : C.text02,
            padding:"10px 20px", fontSize:13,
            fontFamily:"'IBM Plex Sans',sans-serif", cursor:"pointer",
          }}>{pat.name}</button>
        ))}
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1.5fr", gap:2, marginTop:2 }}>
        <div style={{ ...S.tile }}>
          <div style={{ display:"flex", gap:6, marginBottom:12 }}>
            {p.tags.map(t => <Tag key={t} value={t} small />)}
          </div>
          <h3 style={{ margin:"0 0 12px", fontSize:16, fontWeight:400, color:C.text01 }}>{p.name}</h3>
          <p style={{ margin:"0 0 20px", fontSize:13, color:C.text02, lineHeight:1.6 }}>{p.desc}</p>
          <div style={{ borderTop:`1px solid ${C.border}`, paddingTop:14 }}>
            <p style={{ margin:"0 0 10px", fontSize:11, fontWeight:600, color:C.text03,
              letterSpacing:"0.8px", textTransform:"uppercase" }}>Benefits</p>
            {["Zero-downtime algorithm migration","Per-environment rollout control",
              "Immediate rollback capability","Supports hybrid classical+PQC"].map(b => (
              <div key={b} style={{ display:"flex", gap:8, marginBottom:8, alignItems:"center" }}>
                <span style={{ color:C.success }}>✓</span>
                <span style={{ fontSize:13, color:C.text02 }}>{b}</span>
              </div>
            ))}
          </div>
        </div>
        <div style={{ background:"#0a0a0a", borderTop:`1px solid ${C.border}` }}>
          <div style={{ padding:"8px 16px", borderBottom:`1px solid ${C.border}`,
            display:"flex", gap:8, alignItems:"center" }}>
            <Tag value={p.lang.toUpperCase()} small />
          </div>
          <pre style={{ margin:0, padding:20, fontSize:13, lineHeight:1.7,
            color:"#bebebe", fontFamily:"'IBM Plex Mono',monospace",
            overflowX:"auto", whiteSpace:"pre-wrap" }}>{p.code}</pre>
        </div>
      </div>
    </div>
  );
}


// ─── App Shell ────────────────────────────────────────────────────────────────
const NAV = [
  { id: "dashboard", label: "Dashboard",      icon: "◈" },
  { id: "repos",     label: "Projects",        icon: "⬡" },
  { id: "scan",      label: "Scan Explorer",  icon: "◎" },
  { id: "secrets",   label: "File Secrets",   icon: "🔑" },
  { id: "network",   label: "Network / TLS",  icon: "🌐" },
  { id: "runtime",   label: "Runtime Agent",  icon: "📡" },
  { id: "cicd",      label: "CI/CD Gates",    icon: "🚦" },
  { id: "cbom",      label: "CBOM",           icon: "▦" },
  { id: "agility",   label: "Crypto Agility", icon: "⚡" },
];

// ─── File Secrets View ────────────────────────────────────────────────────────
const TYPE_META = {
  SSH_PRIVATE_KEY:  { icon:"🔐", label:"SSH Private Key",   color:"#fa4d56" },
  SSH_PUBLIC_KEY:   { icon:"🔑", label:"SSH Public Key",    color:"#ff832b" },
  AUTHORIZED_KEY:   { icon:"🗝",  label:"Authorized Key",    color:"#ff832b" },
  TLS_CERT:         { icon:"📜", label:"TLS Certificate",   color:"#4589ff" },
  PKCS12:           { icon:"📦", label:"PKCS#12 Bundle",    color:"#a56eff" },
  PKCS12_CHAIN:     { icon:"📦", label:"PKCS#12 Chain",     color:"#a56eff" },
  GPG_KEY:          { icon:"🛡",  label:"GPG Key",           color:"#3ddbd9" },
  SSH_CONFIG:       { icon:"⚙",  label:"SSH Config",        color:"#f1c21b" },
};

const EXPIRY_META = {
  EXPIRED:      { label:"EXPIRED",     color:"#fa4d56" },
  EXPIRES_SOON: { label:"< 30 days",   color:"#fa4d56" },
  EXPIRES_90D:  { label:"< 90 days",   color:"#ff832b" },
  VALID:        { label:"Valid",        color:"#42be65" },
};

function SecretsView() {
  const [findings,  setFindings]  = useState([]);
  const [summary,   setSummary]   = useState(null);
  const [repos,     setRepos]     = useState([]);
  const [projects,  setProjects]  = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [filter,    setFilter]    = useState({ repo_id:"", project_id:"", finding_type:"", risk_level:"" });
  const [expanded,  setExpanded]  = useState(null);

  const load = () => {
    setLoading(true);
    const params = {};
    if (filter.project_id)   params.project_id   = filter.project_id;
    if (filter.repo_id)      params.repo_id      = filter.repo_id;
    if (filter.finding_type) params.finding_type = filter.finding_type;
    if (filter.risk_level)   params.risk_level   = filter.risk_level;
    Promise.all([
      api.getSecrets(params),
      api.getSecretsSummary(),
      api.getRepos(),
      api.getProjects(),
    ]).then(([f, s, r, p]) => { setFindings(f); setSummary(s); setRepos(r); setProjects(p); })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [filter]);

  const repoName = (id) => repos.find(r => r.id === id)?.name || id?.slice(0,8);

  const sel    = (key, val) => setFilter(f => ({ ...f, [key]: val }));
  const riskC  = { CRITICAL:C.error, HIGH:C.warning, MEDIUM:"#f1c21b", LOW:C.success, "":C.text02 };

  return (
    <div>
      <PageHeader title="File Secrets" description="SSH keys, TLS certificates, PKCS#12 bundles, GPG keys and SSH config findings" />

      {/* Summary tiles */}
      {summary && (
        <div style={{ display:"flex", gap:2, flexWrap:"wrap", marginBottom:20 }}>
          <StatTile label="Total Findings"  value={summary.total}    accent={C.interactive} />
          <StatTile label="Expiring / Expired" value={summary.expiring} accent={C.error} />
          {Object.entries(summary.by_risk || {}).map(([r, n]) => (
            <StatTile key={r} label={r} value={n} accent={riskC[r] || C.text02} />
          ))}
        </div>
      )}

      {/* Filters */}
      <div style={{ display:"flex", gap:8, marginBottom:16, flexWrap:"wrap" }}>
        <select value={filter.project_id} onChange={e => { sel("project_id", e.target.value); sel("repo_id", ""); }}
          style={{ ...S.input, width:180 }}>
          <option value="">All projects</option>
          {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <select value={filter.repo_id} onChange={e => sel("repo_id", e.target.value)}
          style={{ ...S.input, width:180 }}>
          <option value="">All repositories</option>
          {repos
            .filter(r => !filter.project_id || r.project_id === filter.project_id)
            .map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select>
        <select value={filter.finding_type} onChange={e => sel("finding_type", e.target.value)}
          style={{ ...S.input, width:200 }}>
          <option value="">All types</option>
          {Object.entries(TYPE_META).map(([k, v]) =>
            <option key={k} value={k}>{v.icon} {v.label}</option>)}
        </select>
        <select value={filter.risk_level} onChange={e => sel("risk_level", e.target.value)}
          style={{ ...S.input, width:160 }}>
          <option value="">All risks</option>
          {["CRITICAL","HIGH","MEDIUM","LOW"].map(r =>
            <option key={r} value={r}>{r}</option>)}
        </select>
        <button onClick={load} style={{ ...S.btnPrimary, padding:"0 16px" }}>↻ Refresh</button>
      </div>

      {loading && <div style={{ color:C.text02, padding:20 }}>Scanning…</div>}
      {!loading && findings.length === 0 && (
        <div style={{ ...S.tile, textAlign:"center", padding:48, color:C.text03 }}>
          <div style={{ fontSize:32, marginBottom:12 }}>🔑</div>
          <div style={{ fontSize:14 }}>No key or certificate findings detected.</div>
          <div style={{ fontSize:12, marginTop:8 }}>
            Re-scan your repos — findings appear when SSH keys, TLS certs, PKCS12 bundles,
            GPG keys or weak SSH config directives are found.
          </div>
        </div>
      )}

      {/* Findings table */}
      {!loading && findings.length > 0 && (
        <div style={{ border:`1px solid ${C.border}` }}>
          {/* Header */}
          <div style={{ display:"grid",
            gridTemplateColumns:"140px 180px 160px 1fr 110px 110px 100px",
            background:C.layer02, borderBottom:`1px solid ${C.border}`,
            padding:"8px 16px", fontSize:11, color:C.text03,
            letterSpacing:"0.8px", textTransform:"uppercase" }}>
            <span>Type</span><span>Repository</span><span>Algorithm</span>
            <span>File / Details</span><span>Risk</span>
            <span>Expires</span><span>Status</span>
          </div>

          {findings.map(f => {
            const meta  = TYPE_META[f.finding_type] || { icon:"?", label:f.finding_type, color:C.text03 };
            const exp   = f.expiry_status ? EXPIRY_META[f.expiry_status] : null;
            const isExp = expanded === f.id;
            return (
              <div key={f.id} style={{ borderBottom:`1px solid ${C.border}`,
                background: isExp ? C.layer02 : "transparent" }}>
                <div onClick={() => setExpanded(isExp ? null : f.id)}
                  style={{ display:"grid",
                    gridTemplateColumns:"140px 180px 160px 1fr 110px 110px 100px",
                    padding:"12px 16px", cursor:"pointer", alignItems:"center",
                    transition:"background 0.1s" }}>

                  {/* Type */}
                  <span style={{ fontSize:12, color: meta.color, fontWeight:600 }}>
                    {meta.icon} {meta.label}
                  </span>

                  {/* Repo */}
                  <span style={{ fontSize:12, color:C.interactive,
                    background:C.layer03, padding:"2px 8px",
                    border:`1px solid ${C.border}`, display:"inline-block",
                    maxWidth:160, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                    {repoName(f.repo_id)}
                  </span>

                  {/* Algorithm */}
                  <div>
                    <div style={{ fontSize:13, color:C.text01, fontWeight:600 }}>{f.algorithm}</div>
                    {f.key_size && <div style={{ fontSize:11, color:C.text03 }}>{f.key_size}-bit</div>}
                    {f.curve    && <div style={{ fontSize:11, color:C.text03 }}>{f.curve}</div>}
                  </div>

                  {/* File */}
                  <FilePath path={f.file_path} />

                  {/* Risk */}
                  <Tag value={f.risk_level} small />

                  {/* Expiry */}
                  {exp
                    ? <span style={{ fontSize:11, color:exp.color, fontWeight:600 }}>
                        {exp.label}<br />
                        <span style={{ fontWeight:400, color:C.text03 }}>{f.not_after}</span>
                      </span>
                    : <span style={{ color:C.text03, fontSize:11 }}>—</span>}

                  {/* Quantum status */}
                  <Tag value={f.quantum_status} small />
                </div>

                {/* Expanded detail */}
                {isExp && (
                  <div style={{ padding:"0 16px 16px 16px",
                    borderTop:`1px solid ${C.border}`, display:"grid",
                    gridTemplateColumns:"1fr 1fr", gap:16 }}>
                    <div>
                      <div style={{ fontSize:11, color:C.text03, marginBottom:8,
                        letterSpacing:"0.8px" }}>DETAILS</div>
                      {f.subject    && <Detail label="Subject"  value={f.subject} />}
                      {f.issuer     && <Detail label="Issuer"   value={f.issuer} />}
                      {f.not_before && <Detail label="Valid from" value={f.not_before} />}
                      {f.not_after  && <Detail label="Expires"  value={f.not_after} exp={exp} />}
                      {f.serial     && <Detail label="Serial"   value={f.serial} mono />}
                      {f.config_value && <Detail label="Config value" value={f.config_value} mono />}
                      {f.context    && <Detail label="Context"  value={f.context} />}
                    </div>
                    <div>
                      <div style={{ fontSize:11, color:C.text03, marginBottom:8,
                        letterSpacing:"0.8px" }}>REMEDIATION</div>
                      {f.nist_replacement && (
                        <div style={{ fontSize:13, color:C.success, marginBottom:12 }}>
                          → {f.nist_replacement}
                        </div>
                      )}
                      {f.finding_type === "SSH_PRIVATE_KEY" && (
                        <div style={{ fontSize:12, color:C.text02, lineHeight:1.7 }}>
                          <div style={{ marginBottom:6 }}>
                            <strong style={{ color:C.text01 }}>Immediate:</strong> Verify this key is not committed to git history.
                          </div>
                          <div style={{ marginBottom:6 }}>
                            <strong style={{ color:C.text01 }}>Generate replacement:</strong>
                            <pre style={{ margin:"4px 0", padding:"6px 10px",
                              background:"#0a0a0a", fontSize:11, color:"#bebebe",
                              fontFamily:"'IBM Plex Mono',monospace" }}>
                              ssh-keygen -t ed25519 -C "your@email.com"
                            </pre>
                          </div>
                          <div>
                            <strong style={{ color:C.text01 }}>Future:</strong> Migrate to ML-DSA-65 (FIPS 204) once OpenSSH adds support.
                          </div>
                        </div>
                      )}
                      {f.finding_type === "TLS_CERT" && (
                        <div style={{ fontSize:12, color:C.text02, lineHeight:1.7 }}>
                          <div style={{ marginBottom:6 }}>
                            <strong style={{ color:C.text01 }}>Re-issue with:</strong> ECDSA P-256 or Ed25519 (classical safe).
                          </div>
                          <div>
                            <strong style={{ color:C.text01 }}>PQC-ready:</strong> Re-issue with hybrid RSA+ML-DSA-65 cert once CA support is available.
                          </div>
                        </div>
                      )}
                      {f.finding_type === "SSH_CONFIG" && (
                        <div style={{ fontSize:12, color:C.text02, lineHeight:1.7 }}>
                          <div style={{ marginBottom:6 }}>
                            <strong style={{ color:C.text01 }}>Recommended ciphers:</strong>
                            <pre style={{ margin:"4px 0", padding:"6px 10px",
                              background:"#0a0a0a", fontSize:11, color:"#bebebe",
                              fontFamily:"'IBM Plex Mono',monospace" }}>
{`Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp521
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256`}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function Detail({ label, value, mono, exp }) {
  return (
    <div style={{ marginBottom:8 }}>
      <span style={{ fontSize:11, color:C.text03, marginRight:8 }}>{label}:</span>
      <span style={{ fontSize:12, color: exp ? exp.color : C.text02,
        fontFamily: mono ? "'IBM Plex Mono',monospace" : "inherit",
        fontSize: mono ? 11 : 12 }}>
        {value}
      </span>
    </div>
  );
}

// ─── Network / TLS View ───────────────────────────────────────────────────────
const QS_COLOR = { BROKEN:"#fa4d56", VULNERABLE:"#ff832b", WEAK:"#f1c21b", MONITOR:"#4589ff", SAFE:"#42be65" };
const RL_COLOR = { CRITICAL:"#fa4d56", HIGH:"#ff832b", MEDIUM:"#f1c21b", LOW:"#42be65" };

function NetworkView() {
  const [findings,  setFindings]  = useState([]);
  const [summary,   setSummary]   = useState(null);
  const [repos,     setRepos]     = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [scanning,  setScanning]  = useState(false);
  const [expanded,  setExpanded]  = useState(null);
  const [endpoint,  setEndpoint]  = useState("");
  const [repoId,    setRepoId]    = useState("");
  const [scanErr,   setScanErr]   = useState(null);
  const [filter,    setFilter]    = useState({ quantum_status:"", risk_level:"" });

  const load = () => {
    setLoading(true);
    const params = {};
    if (filter.quantum_status) params.quantum_status = filter.quantum_status;
    if (filter.risk_level)     params.risk_level     = filter.risk_level;
    Promise.all([
      api.getNetworkFindings(params),
      api.getNetworkSummary(),
      api.getRepos(),
    ]).then(([f, s, r]) => {
      setFindings(f.findings || []);
      setSummary(s);
      setRepos(r);
    }).catch(console.error).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [filter]);

  const doScan = async () => {
    if (!endpoint.trim()) return;
    setScanErr(null);
    setScanning(true);
    try {
      const result = await api.scanEndpoint({ endpoint: endpoint.trim(), repo_id: repoId || null });
      setEndpoint("");
      setRepoId("");
      load();
    } catch (e) {
      setScanErr(e.message);
    } finally {
      setScanning(false);
    }
  };

  const doDelete = async (id) => {
    if (!window.confirm("Delete this scan result?")) return;
    await api.deleteNetworkFinding(id);
    load();
  };

  const tlsColor = (v) => {
    if (!v) return C.text03;
    if (v === "TLSv1.3") return "#42be65";
    if (v === "TLSv1.2") return "#f1c21b";
    return "#fa4d56";
  };

  return (
    <div>
      <PageHeader
        title="Network / TLS Scanner"
        description="Scan live HTTPS endpoints for quantum-vulnerable TLS configurations and certificates"
      />

      {/* Summary tiles */}
      {summary && (
        <div style={{ display:"flex", gap:2, flexWrap:"wrap", marginBottom:20 }}>
          <StatTile label="Endpoints Scanned" value={summary.total}    accent={C.interactive} />
          <StatTile label="Scan Failures"     value={summary.failed}   accent={C.error} />
          {Object.entries(summary.by_quantum_status || {}).map(([s, n]) =>
            <StatTile key={s} label={s} value={n} accent={QS_COLOR[s] || C.text02} />
          )}
        </div>
      )}

      {/* TLS Version distribution */}
      {summary && Object.keys(summary.by_tls_version || {}).length > 0 && (
        <div style={{ ...S.tile, marginBottom:16, display:"flex", gap:24, alignItems:"center",
          flexWrap:"wrap" }}>
          <span style={{ fontSize:11, color:C.text03, letterSpacing:"0.8px",
            textTransform:"uppercase" }}>TLS Versions</span>
          {Object.entries(summary.by_tls_version).map(([v, n]) => (
            <div key={v} style={{ display:"flex", alignItems:"center", gap:6 }}>
              <span style={{ width:10, height:10, borderRadius:2,
                background:tlsColor(v), display:"inline-block" }} />
              <span style={{ fontSize:12, color:C.text02 }}>{v || "Unknown"}</span>
              <span style={{ fontSize:12, color:C.text03 }}>({n})</span>
            </div>
          ))}
        </div>
      )}

      {/* Scan form */}
      <div style={{ ...S.tile, marginBottom:16 }}>
        <div style={{ fontSize:12, color:C.text03, letterSpacing:"0.8px",
          textTransform:"uppercase", marginBottom:12 }}>Scan New Endpoint</div>
        <div style={{ display:"flex", gap:8, flexWrap:"wrap", alignItems:"flex-start" }}>
          <input
            value={endpoint}
            onChange={e => setEndpoint(e.target.value)}
            onKeyDown={e => e.key === "Enter" && doScan()}
            placeholder="host:port  or  https://example.com"
            style={{ ...S.input, width:320 }}
          />
          <select value={repoId} onChange={e => setRepoId(e.target.value)}
            style={{ ...S.input, width:200 }}>
            <option value="">No repo association</option>
            {repos.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
          <button
            onClick={doScan}
            disabled={scanning || !endpoint.trim()}
            style={{ ...S.btnPrimary, padding:"0 20px", opacity: scanning ? 0.6 : 1 }}
          >
            {scanning ? "Scanning…" : "🔍 Scan"}
          </button>
        </div>
        {scanErr && (
          <div style={{ marginTop:10, fontSize:12, color:C.error }}>{scanErr}</div>
        )}
        <div style={{ marginTop:8, fontSize:11, color:C.text03 }}>
          Examples: <code style={{ color:C.text02 }}>example.com</code> &nbsp;·&nbsp;
          <code style={{ color:C.text02 }}>example.com:8443</code> &nbsp;·&nbsp;
          <code style={{ color:C.text02 }}>https://api.example.com</code>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display:"flex", gap:8, marginBottom:16 }}>
        <select value={filter.quantum_status}
          onChange={e => setFilter(f => ({ ...f, quantum_status: e.target.value }))}
          style={{ ...S.input, width:180 }}>
          <option value="">All quantum statuses</option>
          {["BROKEN","VULNERABLE","WEAK","MONITOR","SAFE"].map(s =>
            <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={filter.risk_level}
          onChange={e => setFilter(f => ({ ...f, risk_level: e.target.value }))}
          style={{ ...S.input, width:160 }}>
          <option value="">All risk levels</option>
          {["CRITICAL","HIGH","MEDIUM","LOW"].map(r =>
            <option key={r} value={r}>{r}</option>)}
        </select>
        <button onClick={load} style={{ ...S.btnSecondary, padding:"0 16px" }}>↻ Refresh</button>
      </div>

      {loading && <div style={{ color:C.text02, padding:20 }}>Loading…</div>}

      {!loading && findings.length === 0 && (
        <div style={{ ...S.tile, textAlign:"center", padding:48, color:C.text03 }}>
          <div style={{ fontSize:32, marginBottom:12 }}>🌐</div>
          <div style={{ fontSize:14 }}>No endpoint scans yet.</div>
          <div style={{ fontSize:12, marginTop:8 }}>
            Enter a hostname above and click Scan to check its TLS configuration.
          </div>
        </div>
      )}

      {/* Findings table */}
      {!loading && findings.length > 0 && (
        <div style={{ border:`1px solid ${C.border}` }}>
          {/* Header */}
          <div style={{ display:"grid",
            gridTemplateColumns:"220px 90px 140px 120px 110px 110px 80px",
            background:C.layer02, borderBottom:`1px solid ${C.border}`,
            padding:"8px 16px", fontSize:11, color:C.text03,
            letterSpacing:"0.8px", textTransform:"uppercase" }}>
            <span>Endpoint</span>
            <span>TLS</span>
            <span>Algorithm</span>
            <span>Cipher</span>
            <span>Quantum Risk</span>
            <span>Risk Level</span>
            <span>Actions</span>
          </div>

          {findings.map(f => {
            const isExp = expanded === f.id;
            const failed = f.scan_status === "failed";
            return (
              <div key={f.id} style={{ borderBottom:`1px solid ${C.border}`,
                background: isExp ? C.layer02 : "transparent" }}>
                <div onClick={() => setExpanded(isExp ? null : f.id)}
                  style={{ display:"grid",
                    gridTemplateColumns:"220px 90px 140px 120px 110px 110px 80px",
                    padding:"12px 16px", cursor:"pointer", alignItems:"center" }}>

                  {/* Endpoint */}
                  <div>
                    <div style={{ fontSize:13, color: failed ? C.error : C.interactive,
                      fontFamily:"'IBM Plex Mono',monospace", fontSize:12 }}>
                      {f.endpoint}
                    </div>
                    {failed && (
                      <div style={{ fontSize:11, color:C.error }}>Failed</div>
                    )}
                    <div style={{ fontSize:11, color:C.text03 }}>
                      {f.scanned_at ? new Date(f.scanned_at).toLocaleString() : ""}
                    </div>
                  </div>

                  {/* TLS version */}
                  <span style={{ fontSize:12, fontWeight:600,
                    color:tlsColor(f.tls_version) }}>
                    {f.tls_version || (failed ? "—" : "?")}
                  </span>

                  {/* Algorithm */}
                  <div>
                    <div style={{ fontSize:13, color:C.text01, fontWeight:600 }}>
                      {f.algorithm || "—"}
                    </div>
                    {f.key_size && <div style={{ fontSize:11, color:C.text03 }}>{f.key_size}-bit</div>}
                    {f.key_curve && <div style={{ fontSize:11, color:C.text03 }}>{f.key_curve}</div>}
                  </div>

                  {/* Cipher */}
                  <div style={{ fontSize:11, color:C.text02, fontFamily:"'IBM Plex Mono',monospace",
                    overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                    {f.cipher_name || "—"}
                  </div>

                  {/* Quantum status */}
                  {f.quantum_status
                    ? <span style={{ fontSize:11, fontWeight:700, padding:"2px 8px",
                        background: (QS_COLOR[f.quantum_status] || C.text03) + "22",
                        color: QS_COLOR[f.quantum_status] || C.text03,
                        border:`1px solid ${QS_COLOR[f.quantum_status] || C.text03}` }}>
                        {f.quantum_status}
                      </span>
                    : <span style={{ color:C.text03 }}>—</span>}

                  {/* Risk level */}
                  {f.risk_level
                    ? <span style={{ fontSize:11, fontWeight:700, padding:"2px 8px",
                        background: (RL_COLOR[f.risk_level] || C.text03) + "22",
                        color: RL_COLOR[f.risk_level] || C.text03,
                        border:`1px solid ${RL_COLOR[f.risk_level] || C.text03}` }}>
                        {f.risk_level}
                      </span>
                    : <span style={{ color:C.text03 }}>—</span>}

                  {/* Delete */}
                  <button onClick={e => { e.stopPropagation(); doDelete(f.id); }}
                    style={{ ...S.btnDanger, padding:"2px 8px", fontSize:11 }}>
                    🗑
                  </button>
                </div>

                {/* Expanded detail */}
                {isExp && (
                  <div style={{ padding:"0 16px 16px", borderTop:`1px solid ${C.border}`,
                    display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:16 }}>

                    {/* Cert info */}
                    <div>
                      <div style={{ fontSize:11, color:C.text03, marginBottom:8,
                        letterSpacing:"0.8px", textTransform:"uppercase" }}>Certificate</div>
                      {f.cert_subject   && <Detail label="Subject"    value={f.cert_subject} />}
                      {f.cert_issuer    && <Detail label="Issuer"     value={f.cert_issuer} />}
                      {f.cert_not_before&& <Detail label="Valid from" value={new Date(f.cert_not_before).toLocaleDateString()} />}
                      {f.cert_not_after && <Detail label="Expires"    value={new Date(f.cert_not_after).toLocaleDateString()} />}
                      {f.cert_serial    && <Detail label="Serial"     value={f.cert_serial} mono />}
                      {f.sig_algorithm  && <Detail label="Sig algo"   value={f.sig_algorithm} />}
                    </div>

                    {/* TLS / cipher */}
                    <div>
                      <div style={{ fontSize:11, color:C.text03, marginBottom:8,
                        letterSpacing:"0.8px", textTransform:"uppercase" }}>TLS Details</div>
                      {f.tls_version  && <Detail label="TLS version" value={f.tls_version} />}
                      {f.cipher_name  && <Detail label="Cipher"      value={f.cipher_name} mono />}
                      {f.cipher_bits  && <Detail label="Key exchange bits" value={f.cipher_bits} />}
                      {f.key_type     && <Detail label="Key type"    value={f.key_type} />}
                      {f.key_size     && <Detail label="Key size"    value={`${f.key_size}-bit`} />}
                      {f.key_curve    && <Detail label="Curve"       value={f.key_curve} />}
                      {f.error_message&& <Detail label="Error"       value={f.error_message} />}
                    </div>

                    {/* Remediation */}
                    <div>
                      <div style={{ fontSize:11, color:C.text03, marginBottom:8,
                        letterSpacing:"0.8px", textTransform:"uppercase" }}>Remediation</div>
                      {f.nist_replacement && (
                        <div style={{ fontSize:13, color:C.success, marginBottom:12,
                          fontWeight:600 }}>
                          → {f.nist_replacement}
                        </div>
                      )}
                      {(f.issues || []).length > 0 && (
                        <div>
                          {f.issues.map((issue, i) => (
                            <div key={i} style={{ fontSize:12, color:C.text02,
                              marginBottom:6, display:"flex", gap:6 }}>
                              <span style={{ color:C.warning }}>⚠</span>
                              {issue}
                            </div>
                          ))}
                        </div>
                      )}
                      <div style={{ marginTop:12, fontSize:12, color:C.text02, lineHeight:1.7 }}>
                        <strong style={{ color:C.text01 }}>PQC migration path:</strong><br />
                        Enable TLS 1.3 and plan for hybrid certificates combining classical
                        and ML-KEM/ML-DSA algorithms once CA support is available (RFC 8998).
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Runtime Agent View (Stage 12 — eBPF) ──────────────────────────────────────
function RuntimeView() {
  const [findings, setFindings] = useState([]);
  const [hosts,    setHosts]    = useState([]);
  const [summary,  setSummary]  = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [filter,   setFilter]   = useState({ risk_level:"", quantum_status:"", host_id:"" });
  const [newHost,  setNewHost]  = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [registering, setRegistering] = useState(false);
  const [newToken, setNewToken] = useState(null);

  const load = () => {
    setLoading(true);
    const params = {};
    if (filter.risk_level)     params.risk_level     = filter.risk_level;
    if (filter.quantum_status) params.quantum_status = filter.quantum_status;
    if (filter.host_id)        params.host_id        = filter.host_id;
    Promise.all([
      api.getRuntimeFindings(params),
      api.getRuntimeHosts(),
      api.getRuntimeSummary(),
    ]).then(([f, h, s]) => {
      setFindings(f.findings || []);
      setHosts(h.hosts || []);
      setSummary(s);
    }).catch(console.error).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [filter]);

  const doRegister = async () => {
    if (!newHost.trim()) return;
    setRegistering(true);
    try {
      const result = await api.registerRuntimeHost({ hostname: newHost.trim(), label: newLabel.trim() || null });
      setNewToken(result.token);
      setNewHost("");
      setNewLabel("");
      load();
    } catch (e) {
      console.error(e);
    } finally {
      setRegistering(false);
    }
  };

  const doDeleteHost = async (id) => {
    if (!window.confirm("Remove this host and all its runtime findings?")) return;
    await api.deleteRuntimeHost(id);
    load();
  };

  const doArchive = async (id) => {
    await api.archiveRuntimeFinding(id);
    load();
  };

  return (
    <div>
      <PageHeader
        title="Runtime Agent"
        description="Crypto primitives observed at runtime via the eBPF agent (agent/) — complements the static source scan"
      />

      {/* Summary tiles */}
      {summary && (
        <div style={{ display:"flex", gap:2, flexWrap:"wrap", marginBottom:20 }}>
          <StatTile label="Hosts Reporting" value={summary.total_hosts}    accent={C.interactive} />
          <StatTile label="Runtime Findings" value={summary.total_findings} accent={C.interactive} />
          {Object.entries(summary.by_risk_level || {}).map(([r, n]) =>
            <StatTile key={r} label={r} value={n} accent={C.risk[r] || C.text02} />
          )}
        </div>
      )}

      {/* Register a new host */}
      <div style={{ ...S.tile, marginBottom:16 }}>
        <div style={{ fontSize:12, color:C.text03, letterSpacing:"0.8px",
          textTransform:"uppercase", marginBottom:12 }}>Register Agent Host</div>
        <div style={{ display:"flex", gap:8, flexWrap:"wrap", alignItems:"flex-start" }}>
          <input
            value={newHost}
            onChange={e => setNewHost(e.target.value)}
            onKeyDown={e => e.key === "Enter" && doRegister()}
            placeholder="hostname (e.g. web-01)"
            style={{ ...S.input, width:240 }}
          />
          <input
            value={newLabel}
            onChange={e => setNewLabel(e.target.value)}
            onKeyDown={e => e.key === "Enter" && doRegister()}
            placeholder="label (optional, e.g. prod web tier)"
            style={{ ...S.input, width:280 }}
          />
          <button
            onClick={doRegister}
            disabled={registering || !newHost.trim()}
            style={{ ...S.btnPrimary, padding:"0 20px", opacity: registering ? 0.6 : 1 }}
          >
            {registering ? "Registering…" : "+ Register"}
          </button>
        </div>
        {newToken && (
          <div style={{ marginTop:12, padding:12, background:C.layer02, border:`1px solid ${C.borderStrong}` }}>
            <div style={{ fontSize:11, color:C.text03, marginBottom:4 }}>
              Ingest token (shown once — copy it into the agent's <code>-token</code> flag or <code>PQC_AGENT_TOKEN</code>):
            </div>
            <code style={{ fontSize:12, color:C.success, fontFamily:"'IBM Plex Mono',monospace",
              wordBreak:"break-all" }}>{newToken}</code>
          </div>
        )}
      </div>

      {/* Hosts table */}
      {hosts.length > 0 && (
        <div style={{ border:`1px solid ${C.border}`, marginBottom:16 }}>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 120px 140px 180px 60px",
            background:C.layer02, borderBottom:`1px solid ${C.border}`,
            padding:"8px 16px", fontSize:11, color:C.text03,
            letterSpacing:"0.8px", textTransform:"uppercase" }}>
            <span>Hostname</span>
            <span>Label</span>
            <span>Agent Version</span>
            <span>Kernel Info</span>
            <span>Last Seen</span>
            <span>Actions</span>
          </div>
          {hosts.map(h => (
            <div key={h.id} style={{ display:"grid", gridTemplateColumns:"1fr 1fr 120px 140px 180px 60px",
              padding:"10px 16px", borderBottom:`1px solid ${C.border}`, alignItems:"center" }}>
              <span style={{ fontSize:13, color:C.text01, fontFamily:"'IBM Plex Mono',monospace" }}>{h.hostname}</span>
              <span style={{ fontSize:12, color:C.text02 }}>{h.label || "—"}</span>
              <span style={{ fontSize:12, color:C.text03 }}>{h.agent_version || "—"}</span>
              <span style={{ fontSize:12, color:C.text03 }}>{h.kernel_info || "—"}</span>
              <span style={{ fontSize:12, color:C.text03 }}>
                {h.last_seen_at ? new Date(h.last_seen_at).toLocaleString() : "never"}
              </span>
              <button onClick={() => doDeleteHost(h.id)}
                style={{ ...S.btnDanger, padding:"2px 8px", fontSize:11 }}>🗑</button>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div style={{ display:"flex", gap:8, marginBottom:16 }}>
        <select value={filter.host_id}
          onChange={e => setFilter(f => ({ ...f, host_id: e.target.value }))}
          style={{ ...S.input, width:200 }}>
          <option value="">All hosts</option>
          {hosts.map(h => <option key={h.id} value={h.id}>{h.hostname}</option>)}
        </select>
        <select value={filter.quantum_status}
          onChange={e => setFilter(f => ({ ...f, quantum_status: e.target.value }))}
          style={{ ...S.input, width:180 }}>
          <option value="">All quantum statuses</option>
          {["BROKEN","VULNERABLE","WEAK","MONITOR","SAFE"].map(s =>
            <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={filter.risk_level}
          onChange={e => setFilter(f => ({ ...f, risk_level: e.target.value }))}
          style={{ ...S.input, width:160 }}>
          <option value="">All risk levels</option>
          {["CRITICAL","HIGH","MEDIUM","LOW"].map(r =>
            <option key={r} value={r}>{r}</option>)}
        </select>
        <button onClick={load} style={{ ...S.btnSecondary, padding:"0 16px" }}>↻ Refresh</button>
      </div>

      {loading && <div style={{ color:C.text02, padding:20 }}>Loading…</div>}

      {!loading && hosts.length === 0 && (
        <div style={{ ...S.tile, textAlign:"center", padding:48, color:C.text03 }}>
          <div style={{ fontSize:32, marginBottom:12 }}>📡</div>
          <div style={{ fontSize:14 }}>No agent hosts registered yet.</div>
          <div style={{ fontSize:12, marginTop:8 }}>
            Register a host above, then deploy the agent from <code style={{ color:C.text02 }}>agent/</code> with the
            issued token. See <code style={{ color:C.text02 }}>agent/README.md</code> for build &amp; deploy instructions.
          </div>
        </div>
      )}

      {!loading && hosts.length > 0 && findings.length === 0 && (
        <div style={{ ...S.tile, textAlign:"center", padding:48, color:C.text03 }}>
          <div style={{ fontSize:32, marginBottom:12 }}>📡</div>
          <div style={{ fontSize:14 }}>No runtime findings reported yet.</div>
          <div style={{ fontSize:12, marginTop:8 }}>Waiting for the agent to attach probes and report crypto activity.</div>
        </div>
      )}

      {/* Findings table */}
      {!loading && findings.length > 0 && (
        <div style={{ border:`1px solid ${C.border}` }}>
          <div style={{ display:"grid",
            gridTemplateColumns:"140px 1fr 160px 140px 90px 110px 110px 160px 60px",
            background:C.layer02, borderBottom:`1px solid ${C.border}`,
            padding:"8px 16px", fontSize:11, color:C.text03,
            letterSpacing:"0.8px", textTransform:"uppercase" }}>
            <span>Algorithm</span>
            <span>Symbol</span>
            <span>Process</span>
            <span>Host</span>
            <span>Count</span>
            <span>Quantum</span>
            <span>Risk</span>
            <span>Last Seen</span>
            <span>Actions</span>
          </div>
          {findings.map(f => (
            <div key={f.id} style={{ display:"grid",
              gridTemplateColumns:"140px 1fr 160px 140px 90px 110px 110px 160px 60px",
              padding:"10px 16px", borderBottom:`1px solid ${C.border}`, alignItems:"center" }}>
              <span style={{ fontSize:13, color:C.text01, fontWeight:600 }}>{f.algorithm}</span>
              <span style={{ fontSize:12, color:C.text02, fontFamily:"'IBM Plex Mono',monospace",
                overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                {f.symbol}
                <div style={{ fontSize:10, color:C.text03 }}>{f.library}</div>
              </span>
              <span style={{ fontSize:12, color:C.text02, fontFamily:"'IBM Plex Mono',monospace" }}>
                {f.process_name || "—"}{f.pid ? ` (${f.pid})` : ""}
              </span>
              <span style={{ fontSize:12, color:C.text03 }}>{f.hostname || "—"}</span>
              <span style={{ fontSize:13, color:C.text01 }}>{f.occurrences}</span>
              {f.quantum_status
                ? <span style={{ fontSize:11, fontWeight:700, padding:"2px 8px",
                    background: (QS_COLOR[f.quantum_status] || C.text03) + "22",
                    color: QS_COLOR[f.quantum_status] || C.text03,
                    border:`1px solid ${QS_COLOR[f.quantum_status] || C.text03}` }}>
                    {f.quantum_status}
                  </span>
                : <span style={{ color:C.text03 }}>—</span>}
              {f.risk_level
                ? <span style={{ fontSize:11, fontWeight:700, padding:"2px 8px",
                    background: (RL_COLOR[f.risk_level] || C.text03) + "22",
                    color: RL_COLOR[f.risk_level] || C.text03,
                    border:`1px solid ${RL_COLOR[f.risk_level] || C.text03}` }}>
                    {f.risk_level}
                  </span>
                : <span style={{ color:C.text03 }}>—</span>}
              <span style={{ fontSize:11, color:C.text03 }}>
                {f.last_seen_at ? new Date(f.last_seen_at).toLocaleString() : "—"}
              </span>
              <button onClick={() => doArchive(f.id)}
                style={{ ...S.btnGhost, padding:"2px 8px", fontSize:11 }}>Archive</button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── CI/CD Gates View ─────────────────────────────────────────────────────────
const GATE_COLOR = { PASS:"#42be65", FAIL:"#fa4d56", "—":"#8d8d8d" };

function CICDView() {
  const [status,    setStatus]   = useState(null);
  const [repos,     setRepos]    = useState([]);
  const [selRepo,   setSelRepo]  = useState(null);   // repo object for detail panel
  const [cfg,       setCfg]      = useState(null);
  const [gate,      setGate]     = useState(null);
  const [deliveries,setDeliveries] = useState([]);
  const [saving,    setSaving]   = useState(false);
  const [saveOk,    setSaveOk]   = useState(false);
  const [loading,   setLoading]  = useState(true);

  // draft config state
  const [draft, setDraft] = useState(null);

  const BASE_URL = window.location.origin;

  const loadStatus = () => {
    setLoading(true);
    Promise.all([api.getCICDStatus(), api.getRepos()])
      .then(([s, r]) => { setStatus(s); setRepos(r); })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadStatus(); }, []);

  const selectRepo = (repo) => {
    setSelRepo(repo);
    setSaveOk(false);
    Promise.all([
      api.getCICDConfig(repo.id),
      api.getCICDGate(repo.id),
      api.getCICDDeliveries(repo.id),
    ]).then(([c, g, d]) => {
      setCfg(c);
      setDraft({
        fail_on_broken:     c.fail_on_broken,
        fail_on_vulnerable: c.fail_on_vulnerable,
        fail_on_weak:       c.fail_on_weak,
        fail_on_critical:   c.fail_on_critical,
        fail_on_high:       c.fail_on_high,
        webhook_secret:     "",
      });
      setGate(g);
      setDeliveries(d);
    }).catch(console.error);
  };

  const saveConfig = async () => {
    if (!selRepo || !draft) return;
    setSaving(true);
    try {
      const saved = await api.saveCICDConfig(selRepo.id, draft);
      setCfg(saved);
      setSaveOk(true);
      setDraft(d => ({ ...d, webhook_secret: "" }));
      const g = await api.getCICDGate(selRepo.id);
      setGate(g);
      loadStatus();
    } catch (e) {
      alert("Save failed: " + e.message);
    } finally {
      setSaving(false);
    }
  };

  const toggle = (key) => setDraft(d => ({ ...d, [key]: !d[key] }));

  const webhookUrl = selRepo
    ? `${BASE_URL}/api/cicd/webhook/${selRepo.id}`
    : "";
  const badgeUrl = selRepo
    ? `${BASE_URL}/api/cicd/badge/${selRepo.id}.svg`
    : "";
  const badgeMd = selRepo
    ? `![PQC Gate](${BASE_URL}/api/cicd/badge/${selRepo.id}.svg)`
    : "";
  const riskBadgeMd = selRepo
    ? `![PQC Risk](${BASE_URL}/api/cicd/risk-badge/${selRepo.id}.svg)`
    : "";
  const gateSnippet = selRepo ? `# In your CI pipeline (e.g. GitHub Actions step):
- name: PQC Gate Check
  run: |
    RESULT=$(curl -sf ${BASE_URL}/api/cicd/gate/${selRepo.id})
    echo "$RESULT"
    echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d['passed'] else 1)"` : "";

  return (
    <div>
      <PageHeader
        title="CI/CD Gates"
        description="Configure per-repo quality gates, receive push webhooks, and embed pass/fail badges"
      />

      {/* Overview summary tiles */}
      {status && (
        <div style={{ display:"flex", gap:2, flexWrap:"wrap", marginBottom:20 }}>
          <StatTile label="Total Repos"  value={status.total}       accent={C.interactive} />
          <StatTile label="Passing"      value={status.passing}     accent="#42be65" />
          <StatTile label="Failing"      value={status.failing}     accent="#fa4d56" />
          <StatTile label="Not Scanned"  value={status.not_scanned} accent={C.text03} />
        </div>
      )}

      <div style={{ display:"grid", gridTemplateColumns:"300px 1fr", gap:16 }}>

        {/* Left — repo list */}
        <div style={{ border:`1px solid ${C.border}` }}>
          <div style={{ background:C.layer02, padding:"8px 16px", fontSize:11,
            color:C.text03, letterSpacing:"0.8px", textTransform:"uppercase",
            borderBottom:`1px solid ${C.border}` }}>Repositories</div>
          {loading && <div style={{ padding:16, color:C.text03, fontSize:12 }}>Loading…</div>}
          {!loading && (status?.repos || []).map(r => {
            const isActive = selRepo?.id === r.repo_id;
            const gs = r.gate_status || "—";
            return (
              <div key={r.repo_id}
                onClick={() => selectRepo(repos.find(x => x.id === r.repo_id) || { id: r.repo_id, name: r.repo_name })}
                style={{ padding:"10px 16px", cursor:"pointer", borderBottom:`1px solid ${C.border}`,
                  background: isActive ? C.layer02 : "transparent",
                  borderLeft: isActive ? `3px solid ${C.interactive}` : "3px solid transparent" }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                  <span style={{ fontSize:13, color:C.text01,
                    maxWidth:180, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                    {r.repo_name}
                  </span>
                  <span style={{ fontSize:11, fontWeight:700, padding:"1px 6px",
                    background: (GATE_COLOR[gs] || C.text03) + "22",
                    color: GATE_COLOR[gs] || C.text03,
                    border:`1px solid ${GATE_COLOR[gs] || C.text03}` }}>
                    {gs}
                  </span>
                </div>
                <div style={{ fontSize:11, color:C.text03, marginTop:2 }}>
                  {r.failure_count > 0
                    ? `${r.failure_count} gate failure${r.failure_count > 1 ? "s" : ""}`
                    : r.last_scanned_at ? "All gates passing" : "Not yet scanned"}
                </div>
              </div>
            );
          })}
        </div>

        {/* Right — detail panel */}
        {!selRepo && (
          <div style={{ ...S.tile, display:"flex", alignItems:"center", justifyContent:"center",
            color:C.text03, flexDirection:"column", gap:12, minHeight:300 }}>
            <div style={{ fontSize:32 }}>🚦</div>
            <div style={{ fontSize:14 }}>Select a repository to configure its CI/CD gate</div>
          </div>
        )}

        {selRepo && draft && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>

            {/* Gate result */}
            {gate && (
              <div style={{ ...S.tile, borderLeft:`4px solid ${GATE_COLOR[gate.status] || C.border}` }}>
                <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:12 }}>
                  <span style={{ fontSize:22 }}>{gate.passed ? "✅" : "❌"}</span>
                  <div>
                    <div style={{ fontSize:16, fontWeight:600,
                      color: gate.passed ? "#42be65" : "#fa4d56" }}>
                      Gate {gate.status}
                    </div>
                    <div style={{ fontSize:12, color:C.text03 }}>
                      {gate.counts.total} findings · {gate.counts.broken} BROKEN ·{" "}
                      {gate.counts.vulnerable} VULNERABLE · {gate.counts.weak} WEAK
                    </div>
                  </div>
                </div>
                {!gate.passed && gate.failures.slice(0, 5).map((f, i) => (
                  <div key={i} style={{ fontSize:11, color:"#fa4d56", marginBottom:4,
                    fontFamily:"'IBM Plex Mono',monospace" }}>
                    ✗ {f}
                  </div>
                ))}
                {gate.failures.length > 5 && (
                  <div style={{ fontSize:11, color:C.text03 }}>
                    …and {gate.failures.length - 5} more
                  </div>
                )}
              </div>
            )}

            {/* Gate config */}
            <div style={S.tile}>
              <div style={{ fontSize:12, color:C.text03, letterSpacing:"0.8px",
                textTransform:"uppercase", marginBottom:14 }}>Gate Thresholds</div>

              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8, marginBottom:16 }}>
                {[
                  { key:"fail_on_broken",     label:"Fail on BROKEN quantum status" },
                  { key:"fail_on_vulnerable",  label:"Fail on VULNERABLE quantum status" },
                  { key:"fail_on_weak",        label:"Fail on WEAK quantum status" },
                  { key:"fail_on_critical",    label:"Fail on CRITICAL risk level" },
                  { key:"fail_on_high",        label:"Fail on HIGH risk level" },
                ].map(({ key, label }) => (
                  <label key={key} style={{ display:"flex", alignItems:"center", gap:8,
                    cursor:"pointer", fontSize:13, color:C.text01 }}>
                    <input type="checkbox" checked={!!draft[key]}
                      onChange={() => toggle(key)}
                      style={{ accentColor:C.interactive, width:16, height:16 }} />
                    {label}
                  </label>
                ))}
              </div>

              <div style={{ fontSize:12, color:C.text03, letterSpacing:"0.8px",
                textTransform:"uppercase", marginBottom:8 }}>Webhook Secret (optional)</div>
              <input
                type="password"
                value={draft.webhook_secret}
                onChange={e => setDraft(d => ({ ...d, webhook_secret: e.target.value }))}
                placeholder={cfg?.has_secret ? "••••••••  (leave blank to keep existing)" : "Set a shared secret"}
                style={{ ...S.input, width:"100%", maxWidth:400, marginBottom:16 }}
              />

              <div style={{ display:"flex", alignItems:"center", gap:12 }}>
                <button onClick={saveConfig} disabled={saving}
                  style={{ ...S.btnPrimary, padding:"0 20px", opacity: saving ? 0.6 : 1 }}>
                  {saving ? "Saving…" : "💾 Save Config"}
                </button>
                {saveOk && <span style={{ fontSize:12, color:"#42be65" }}>✓ Saved</span>}
              </div>
            </div>

            {/* Webhook setup */}
            <div style={S.tile}>
              <div style={{ fontSize:12, color:C.text03, letterSpacing:"0.8px",
                textTransform:"uppercase", marginBottom:14 }}>Webhook Setup</div>

              <div style={{ marginBottom:12 }}>
                <div style={{ fontSize:11, color:C.text03, marginBottom:4 }}>Webhook URL</div>
                <div style={{ display:"flex", gap:8 }}>
                  <code style={{ fontSize:12, color:C.text02, background:C.layer03,
                    padding:"6px 12px", flex:1, fontFamily:"'IBM Plex Mono',monospace",
                    border:`1px solid ${C.border}`, wordBreak:"break-all" }}>
                    {webhookUrl}
                  </code>
                  <button onClick={() => navigator.clipboard.writeText(webhookUrl)}
                    style={{ ...S.btnSecondary, padding:"0 12px", fontSize:12, whiteSpace:"nowrap" }}>
                    Copy
                  </button>
                </div>
              </div>

              <div style={{ fontSize:12, color:C.text02, lineHeight:1.8 }}>
                <strong style={{ color:C.text01 }}>GitHub:</strong> Settings → Webhooks → Add webhook<br />
                Content type: <code style={{ color:C.text02 }}>application/json</code> ·
                Events: <code style={{ color:C.text02 }}>Just the push event</code>
              </div>
              <div style={{ fontSize:12, color:C.text02, marginTop:6, lineHeight:1.8 }}>
                <strong style={{ color:C.text01 }}>GitLab:</strong> Settings → Webhooks ·
                Check <em>Push events</em> · Set the secret token above as the <em>Secret token</em>
              </div>
            </div>

            {/* Badge snippets */}
            <div style={S.tile}>
              <div style={{ fontSize:12, color:C.text03, letterSpacing:"0.8px",
                textTransform:"uppercase", marginBottom:14 }}>README Badges</div>

              {[
                { label:"Gate status badge", md: badgeMd },
                { label:"Risk level badge",  md: riskBadgeMd },
              ].map(({ label, md }) => (
                <div key={label} style={{ marginBottom:16 }}>
                  <div style={{ fontSize:11, color:C.text03, marginBottom:6 }}>{label}</div>
                  <div style={{ display:"flex", gap:8, alignItems:"flex-start" }}>
                    <code style={{ fontSize:11, color:C.text02, background:C.layer03,
                      padding:"6px 12px", flex:1, fontFamily:"'IBM Plex Mono',monospace",
                      border:`1px solid ${C.border}`, wordBreak:"break-all" }}>
                      {md}
                    </code>
                    <button onClick={() => navigator.clipboard.writeText(md)}
                      style={{ ...S.btnSecondary, padding:"0 12px", fontSize:12, whiteSpace:"nowrap" }}>
                      Copy
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* CI step snippet */}
            <div style={S.tile}>
              <div style={{ fontSize:12, color:C.text03, letterSpacing:"0.8px",
                textTransform:"uppercase", marginBottom:14 }}>CI Step — Gate Check</div>
              <div style={{ display:"flex", gap:8, alignItems:"flex-start" }}>
                <pre style={{ fontSize:11, color:"#bebebe", background:"#0a0a0a",
                  padding:"12px 16px", flex:1, fontFamily:"'IBM Plex Mono',monospace",
                  border:`1px solid ${C.border}`, margin:0, whiteSpace:"pre-wrap",
                  wordBreak:"break-all" }}>
                  {gateSnippet}
                </pre>
                <button onClick={() => navigator.clipboard.writeText(gateSnippet)}
                  style={{ ...S.btnSecondary, padding:"0 12px", fontSize:12, whiteSpace:"nowrap" }}>
                  Copy
                </button>
              </div>
            </div>

            {/* Webhook delivery log */}
            <div style={S.tile}>
              <div style={{ fontSize:12, color:C.text03, letterSpacing:"0.8px",
                textTransform:"uppercase", marginBottom:14 }}>Recent Webhook Deliveries</div>
              {deliveries.length === 0 && (
                <div style={{ fontSize:12, color:C.text03 }}>
                  No deliveries yet. Push a commit after configuring the webhook above.
                </div>
              )}
              {deliveries.length > 0 && (
                <div style={{ border:`1px solid ${C.border}` }}>
                  <div style={{ display:"grid",
                    gridTemplateColumns:"160px 80px 100px 120px 1fr",
                    background:C.layer02, borderBottom:`1px solid ${C.border}`,
                    padding:"6px 12px", fontSize:11, color:C.text03,
                    letterSpacing:"0.8px", textTransform:"uppercase" }}>
                    <span>Received</span><span>Provider</span>
                    <span>Event</span><span>Branch</span><span>Status</span>
                  </div>
                  {deliveries.map(d => (
                    <div key={d.id} style={{ display:"grid",
                      gridTemplateColumns:"160px 80px 100px 120px 1fr",
                      padding:"8px 12px", borderBottom:`1px solid ${C.border}`,
                      fontSize:12, alignItems:"center" }}>
                      <span style={{ color:C.text03 }}>
                        {d.received_at ? new Date(d.received_at).toLocaleString() : "—"}
                      </span>
                      <span style={{ color:C.text02 }}>{d.provider || "—"}</span>
                      <span style={{ color:C.text02 }}>{d.event_type || "—"}</span>
                      <span style={{ color:C.interactive, fontFamily:"'IBM Plex Mono',monospace",
                        fontSize:11 }}>{d.branch || "—"}</span>
                      <span style={{ color:
                        d.status === "scan_queued" ? "#42be65" :
                        d.status === "ignored"     ? C.text03  :
                        d.status === "error"       ? "#fa4d56" : C.text02 }}>
                        {d.status}
                        {d.triggered_scan_id && (
                          <span style={{ fontSize:10, color:C.text03, marginLeft:6 }}>
                            scan {d.triggered_scan_id.slice(0,8)}
                          </span>
                        )}
                        {d.error && <span style={{ fontSize:10, color:"#fa4d56", marginLeft:6 }}>{d.error}</span>}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const VIEWS = { dashboard: DashboardView, repos: ProjectsView, scan: ScanExplorerView, secrets: SecretsView, network: NetworkView, runtime: RuntimeView, cicd: CICDView, cbom: CBOMView, agility: AgilityView };

// ─── Role colours ────────────────────────────────────────────────────────────
const ROLE_COLOR = { admin:"#ff832b", dev:"#4589ff", reader:"#42be65" };

// ─── Login Page ───────────────────────────────────────────────────────────────

function LoginPage({ onLogin }) {
  const [username,  setUsername]  = useState("");
  const [password,  setPassword]  = useState("");
  const [showPass,  setShowPass]  = useState(false);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState(null);

  const submit = async () => {
    if (!username.trim() || !password.trim()) {
      setError("Please enter username and password"); return;
    }
    setLoading(true); setError(null);
    try {
      const user = await api.login({ username: username.trim(), password });
      onLogin(user);
    } catch (e) {
      setError("Invalid username or password");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight:"100vh", background:C.bg, display:"flex", flexDirection:"column",
      fontFamily:"'IBM Plex Sans',sans-serif", color:C.text01 }}>

      {/* Top bar */}
      <header style={{ height:48, background:"#161616", borderBottom:`1px solid ${C.border}`,
        display:"flex", alignItems:"center", padding:"0 24px", gap:12 }}>
        <svg width="20" height="20" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="50" cy="50" r="8" fill="#fff"/>
          <ellipse cx="50" cy="50" rx="38" ry="14" stroke="#fff" strokeWidth="2.5" transform="rotate(0 50 50)"/>
          <ellipse cx="50" cy="50" rx="38" ry="14" stroke="#fff" strokeWidth="2.5" transform="rotate(60 50 50)"/>
          <ellipse cx="50" cy="50" rx="38" ry="14" stroke="#fff" strokeWidth="2.5" transform="rotate(120 50 50)"/>
        </svg>
        <span style={{ width:1, height:16, background:C.border }} />
        <span style={{ fontSize:14, color:C.text01 }}>PQCScanner</span>
        <span style={{ marginLeft:"auto", fontSize:11, color:C.text03 }}>v2.0.0</span>
      </header>

      {/* Main */}
      <div style={{ flex:1, display:"flex", alignItems:"center", justifyContent:"center",
        padding:24, gap:48, flexWrap:"wrap" }}>

        {/* Left — branding */}
        <div style={{ maxWidth:420 }}>
          <div style={{ fontSize:11, color:C.interactive, letterSpacing:"1.2px",
            textTransform:"uppercase", marginBottom:12 }}>Post-Quantum Cryptography</div>
          <h1 style={{ fontSize:36, fontWeight:300, color:C.text01, margin:"0 0 16px",
            lineHeight:1.2 }}>
            Migration<br />
            <span style={{ fontWeight:600 }}>Platform</span>
          </h1>
          <p style={{ fontSize:15, color:C.text02, lineHeight:1.7, marginBottom:32 }}>
            Discover, track, and remediate quantum-vulnerable cryptography across your
            entire codebase. Aligned with NIST FIPS 203, 204, and 205.
          </p>

          {/* Feature list */}
          {[
            { icon:"◎", label:"Multi-language crypto scanner" },
            { icon:"⬡", label:"Per-repo agility scoring (L1–L5)" },
            { icon:"◈", label:"CycloneDX 1.5 CBOM export" },
            { icon:"📋", label:"Remediation playbooks with code diffs" },
          ].map(f => (
            <div key={f.label} style={{ display:"flex", gap:12, marginBottom:12,
              alignItems:"center" }}>
              <span style={{ color:C.interactive, fontSize:18, width:24,
                textAlign:"center" }}>{f.icon}</span>
              <span style={{ fontSize:14, color:C.text02 }}>{f.label}</span>
            </div>
          ))}
        </div>

        {/* Right — login form */}
        <div style={{ width:420 }}>
          <div style={{ background:C.layer01, border:`1px solid ${C.border}`, padding:40 }}>
            <h2 style={{ margin:"0 0 8px", fontSize:20, fontWeight:600, color:C.text01 }}>
              Sign in
            </h2>
            <p style={{ margin:"0 0 28px", fontSize:13, color:C.text03 }}>
              Use a sample account below or enter your credentials
            </p>

            {error && (
              <div style={{ background:"#2d0709", border:`1px solid ${C.error}44`,
                borderLeft:`3px solid ${C.error}`, padding:"10px 14px",
                marginBottom:20, fontSize:13, color:C.error }}>
                ⚠ {error}
              </div>
            )}

            {/* Username */}
            <div style={{ marginBottom:20 }}>
              <label style={{ display:"block", fontSize:12, color:C.text02,
                marginBottom:6, letterSpacing:"0.32px" }}>USERNAME</label>
              <input
                value={username}
                onChange={e => { setUsername(e.target.value); setError(null); setFillUser(null); }}
                onKeyDown={e => e.key === "Enter" && submit()}
                placeholder="Enter username"
                autoComplete="username"
                style={{ width:"100%", height:48, background:C.layer02,
                  border:"none", borderBottom:`2px solid ${C.borderStrong}`,
                  color:C.text01, padding:"0 16px", fontSize:14, outline:"none",
                  boxSizing:"border-box", fontFamily:"'IBM Plex Sans',sans-serif",
                  transition:"border-color 0.15s" }}
                onFocus={e => e.target.style.borderBottomColor = C.interactive}
                onBlur={e  => e.target.style.borderBottomColor = C.borderStrong}
              />
            </div>

            {/* Password */}
            <div style={{ marginBottom:28 }}>
              <label style={{ display:"block", fontSize:12, color:C.text02,
                marginBottom:6, letterSpacing:"0.32px" }}>PASSWORD</label>
              <div style={{ position:"relative" }}>
                <input
                  type={showPass ? "text" : "password"}
                  value={password}
                  onChange={e => { setPassword(e.target.value); setError(null); }}
                  onKeyDown={e => e.key === "Enter" && submit()}
                  placeholder="Enter password"
                  autoComplete="current-password"
                  style={{ width:"100%", height:48, background:C.layer02,
                    border:"none", borderBottom:`2px solid ${C.borderStrong}`,
                    color:C.text01, padding:"0 48px 0 16px", fontSize:14,
                    outline:"none", boxSizing:"border-box",
                    fontFamily:"'IBM Plex Sans',sans-serif" }}
                  onFocus={e => e.target.style.borderBottomColor = C.interactive}
                  onBlur={e  => e.target.style.borderBottomColor = C.borderStrong}
                />
                <button onClick={() => setShowPass(s => !s)} style={{
                  position:"absolute", right:12, top:"50%", transform:"translateY(-50%)",
                  background:"none", border:"none", color:C.text03, cursor:"pointer",
                  fontSize:16, padding:4 }}>
                  {showPass ? "🙈" : "👁"}
                </button>
              </div>
            </div>

            {/* Submit */}
            <button onClick={submit} disabled={loading} style={{
              width:"100%", height:48, background: loading ? C.layer03 : C.interactive,
              border:"none", color:"#fff", fontSize:14, fontWeight:600,
              cursor: loading ? "default" : "pointer",
              fontFamily:"'IBM Plex Sans',sans-serif", letterSpacing:"0.32px",
              transition:"background 0.15s" }}>
              {loading ? "Signing in…" : "Sign in →"}
            </button>
          </div>


        </div>
      </div>

      {/* Footer */}
      <footer style={{ padding:"16px 24px", borderTop:`1px solid ${C.border}`,
        display:"flex", justifyContent:"space-between", fontSize:11, color:C.text03 }}>
        <span>PQCScanner — aligned with NIST SP 800-235 and CycloneDX 1.5</span>
        <span>FIPS 203 · FIPS 204 · FIPS 205</span>
      </footer>
    </div>
  );
}

export default function App() {
  const [page, setPage]       = useState("dashboard");
  const [connected, setConnected] = useState(null);
  const [user, setUser]       = useState(null);   // null = not logged in
  const [authLoading, setAuthLoading] = useState(true);
  const ActiveView = VIEWS[page] || DashboardView;

  // Check existing session on mount
  useEffect(() => {
    api.me()
      .then(u => setUser(u))
      .catch(() => setUser(null))
      .finally(() => setAuthLoading(false));
    api.health().then(() => setConnected(true)).catch(() => setConnected(false));
  }, []);

  const handleLogin = (u) => setUser(u);

  const handleLogout = async () => {
    try { await api.logout(); } catch {}
    setUser(null);
    setPage("dashboard");
  };

  if (authLoading) return (
    <div style={{ minHeight:"100vh", background:C.bg, display:"flex",
      alignItems:"center", justifyContent:"center", fontFamily:"'IBM Plex Sans',sans-serif" }}>
      <div style={{ color:C.text03, fontSize:14 }}>Loading…</div>
    </div>
  );

  if (!user) return <LoginPage onLogin={handleLogin} />;

  return (
    <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", background: C.bg, color: C.text01, minHeight: "100vh" }}>
      {/* Carbon header */}
      <header style={{ background: "#161616", height: 48, borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", position: "fixed", top: 0, left: 0, right: 0, zIndex: 1000 }}>
        <div style={{ width: 256, padding: "0 16px", display: "flex", alignItems: "center", gap: 8, borderRight: `1px solid ${C.border}`, height: "100%" }}>
          <svg width="20" height="20" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="50" cy="50" r="8" fill="#fff"/>
            <ellipse cx="50" cy="50" rx="38" ry="14" stroke="#fff" strokeWidth="2.5" transform="rotate(0 50 50)"/>
            <ellipse cx="50" cy="50" rx="38" ry="14" stroke="#fff" strokeWidth="2.5" transform="rotate(60 50 50)"/>
            <ellipse cx="50" cy="50" rx="38" ry="14" stroke="#fff" strokeWidth="2.5" transform="rotate(120 50 50)"/>
          </svg>
          <span style={{ fontSize: 14, color: C.text01, fontWeight: 400 }}>PQCScanner</span>
        </div>
        <nav style={{ display: "flex", height: "100%", flex: 1 }}>
          {NAV.map(n => (
            <button key={n.id} onClick={() => setPage(n.id)} style={{
              background: page === n.id ? C.layer02 : "none", border: "none",
              borderBottom: page === n.id ? `3px solid ${C.interactive}` : "3px solid transparent",
              color: page === n.id ? C.text01 : C.text02,
              padding: "0 16px", fontSize: 14, fontFamily: "'IBM Plex Sans', sans-serif",
              cursor: "pointer", height: "100%", display: "flex", alignItems: "center", gap: 6,
            }}>
              {n.icon} {n.label}
            </button>
          ))}
        </nav>
        {/* User info + logout */}
        <div style={{ padding: "0 16px", display:"flex", alignItems:"center", gap:12,
          borderLeft:`1px solid ${C.border}`, height:"100%" }}>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{ width:28, height:28, borderRadius:"50%",
              background: (ROLE_COLOR[user.role] || C.interactive) + "33",
              border:`1px solid ${(ROLE_COLOR[user.role] || C.interactive)}66`,
              display:"flex", alignItems:"center", justifyContent:"center",
              fontSize:12, color: ROLE_COLOR[user.role] || C.interactive, fontWeight:600 }}>
              {user.name?.[0] || user.username?.[0] || "U"}
            </div>
            <div>
              <div style={{ fontSize:12, color:C.text01, lineHeight:1.2 }}>{user.name}</div>
              <div style={{ fontSize:10, color: ROLE_COLOR[user.role] || C.text03 }}>
                {user.role?.toUpperCase()}
              </div>
            </div>
          </div>
          <div style={{ width:1, height:20, background:C.border }} />
          <div style={{ fontSize:11, display:"flex", alignItems:"center", gap:6,
            color: connected === true ? C.success : connected === false ? C.error : C.text03 }}>
            <span style={{ fontSize:8 }}>●</span>
            {connected === true ? "Connected" : connected === false ? "Offline" : "…"}
          </div>
          <div style={{ width:1, height:20, background:C.border }} />
          <button onClick={handleLogout} style={{ background:"none", border:"none",
            color:C.text02, cursor:"pointer", fontSize:12, padding:"4px 8px",
            fontFamily:"'IBM Plex Sans',sans-serif",
            display:"flex", alignItems:"center", gap:4 }}>
            ⎋ Sign out
          </button>
        </div>
      </header>

      {/* Offline banner */}
      {connected === false && (
        <div style={{ position: "fixed", top: 48, left: 0, right: 0, zIndex: 999, background: "#2d2000", borderBottom: `1px solid ${C.warning}`, padding: "10px 24px", fontSize: 13, color: C.warning }}>
          ⚠ Backend not reachable — run: <code style={{ color: C.text01, background: C.layer02, padding: "1px 6px" }}>docker-compose up backend</code>
        </div>
      )}

      {/* Main content */}
      <main style={{ marginTop: 48, padding: "0 24px 24px", minHeight: "calc(100vh - 48px)" }}>
        <UserContext.Provider value={user}>
          <ActiveView />
        </UserContext.Provider>
      </main>
    </div>
  );
}
