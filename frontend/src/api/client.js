// Empty API_BASE — Vite proxy forwards /api/* to http://backend:8000
async function req(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  getRepos:           ()     => req("GET",    "/api/repos/"),
  addRepo:            (d)    => req("POST",   "/api/repos/", d),
  deleteRepo:         (id)   => req("DELETE", `/api/repos/${id}`),
  triggerScan:        (id)   => req("POST",   `/api/scans/${id}/trigger`),
  getScanRuns:        (id)   => req("GET",    `/api/scans/${id}/runs`),
  getScanRun:         (id)   => req("GET",    `/api/scans/runs/${id}`),
  getFindings:        (p)    => req("GET",    `/api/findings/?${new URLSearchParams(p||{})}`),
  getFindingsSummary: ()     => req("GET",    "/api/findings/summary"),
  getCBOM:            ()     => req("GET",    "/api/cbom/"),
  exportCycloneDX:    ()     => req("GET",    "/api/cbom/export/cyclonedx"),
  getDashboard:       ()     => req("GET",    "/api/reports/dashboard"),
};
