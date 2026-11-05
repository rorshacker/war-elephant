import { useEffect, useState } from "react";
import { createApi, type Api } from "./api";

type Row = Record<string, any>;

function messageFrom(err: unknown) {
  return err instanceof Error ? err.message : "Request failed";
}
const NAV = [
  ["prep", "Preparation"],
  ["discovery", "Discovery"],
  ["inventory", "Inventory"],
  ["baselines", "Scan"],
  ["jobs", "Jobs"],
  ["findings", "Findings"],
  ["approvals", "Approvals"],
  ["execution", "Execution"],
  ["audit", "Summary"],
] as const;

const GROUPS = [
  { title: "Prepare", ids: ["prep", "discovery", "inventory", "jobs"] },
  { title: "Decide", ids: ["baselines", "findings", "approvals"] },
  { title: "Change", ids: ["execution", "audit"] },
] as const;

const LEAD: Record<(typeof NAV)[number][0], string> = {
  discovery: "Import addresses, a spreadsheet, or computer objects from Active Directory. None of these approves a scan.",
  prep: "Upload the STIG checklist and the ECU, FAM, MSU, and IAVA files you want available. A local checksum is not publisher authentication, and imported text is not executed.",
  inventory: "Confirm which records are the same asset. Addresses alone do not merge identities.",
  baselines: "Choose which uploaded files to scan. The assets listed here are the ones selected in Inventory. A scan does not change a host.",
  jobs: "Running work stays on this tab after you leave the page that started it. The bar shows that the request is still going. It is not a percent of a host being changed.",
  findings: "See what is already recorded and what still needs to be applied. Nothing here changes a host.",
  approvals: "See the selected assets, the change that would be applied, and what can stop it. Approving a hash does not run the change.",
  execution: "Approve a change, then execute it. Approval alone does not write the file.",
  audit: "A record of what was stored: scans, findings, jobs, and changes. Export does not change a host.",
};

export function App() {
  const [section, setSection] = useState<(typeof NAV)[number][0]>("prep");
  const [error, setError] = useState("");
  const [jobs, setJobs] = useState<Row[]>([]);
  const api = createApi(null);
  const track = async (label: string, work: () => Promise<void>) => {
    const id = crypto.randomUUID();
    setJobs((current) => [{ id, label, status: "running", detail: "Working." }, ...current]);
    try {
      await work();
      setJobs((current) => current.map((job) => job.id === id ? { ...job, status: "completed", detail: "Finished." } : job));
    } catch (err) {
      setJobs((current) => current.map((job) => job.id === id ? { ...job, status: "failed", detail: messageFrom(err) } : job));
      throw err;
    }
  };

  return (
    <div className="app">
      <aside className="rail">
        <div className="brand">
          <img src="/emblem.jpg" alt="Navy Blue Team Norfolk emblem" width={56} height={56} />
          <div>
            <strong>War Elephant</strong>
            <span>Offline checklist workbench</span>
          </div>
        </div>
        <nav>
          {GROUPS.map((group) => (
            <div key={group.title} className="nav-group">
              <p className="nav-label">{group.title}</p>
              {group.ids.map((id) => {
                const label = NAV.find(([item]) => item === id)?.[1];
                return (
                  <button key={id} className={section === id ? "active" : ""} onClick={() => setSection(id)}>
                    {label}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>
      <main className="main">
        <div className="top">
          <div>
            <h1>{NAV.find(([id]) => id === section)?.[1]}</h1>
            <p className="lead">{LEAD[section]}</p>
          </div>
        </div>
        {error && <div className="error">{error}</div>}
        {section === "prep" && <Prep api={api} onError={setError} />}
        {section === "discovery" && <Discovery api={api} onError={setError} onTrack={track} />}
        {section === "inventory" && <Inventory api={api} onError={setError} />}
        {section === "baselines" && <Baselines api={api} onError={setError} onTrack={track} />}
        {section === "jobs" && <Jobs api={api} onError={setError} live={jobs} />}
        {section === "findings" && <Findings api={api} onError={setError} onTrack={track} />}
        {section === "approvals" && <Approvals api={api} onError={setError} />}
        {section === "execution" && <Execution api={api} onError={setError} onTrack={track} />}
        {section === "audit" && <Audit api={api} onError={setError} />}
      </main>
    </div>
  );
}

function Prep({ api, onError }: { api: Api; onError: (message: string) => void }) {
  const [packages, setPackages] = useState<Row[]>([]);
  const [benchmarks, setBenchmarks] = useState<Row[]>([]);
  const [updates, setUpdates] = useState<Row[]>([]);
  const reload = async () => {
    setPackages(await api.request("/api/stig/packages"));
    setBenchmarks(await api.request("/api/stig/benchmarks"));
    setUpdates(await api.request("/api/updates"));
  };
  useEffect(() => { void reload().catch((err) => onError(messageFrom(err))); }, []);
  return <MaterialBoard api={api} packages={packages} benchmarks={benchmarks} updates={updates} onImported={reload} onError={onError} />;
}

function Discovery({ api, onError, onTrack }: { api: Api; onError: (message: string) => void; onTrack: (label: string, work: () => Promise<void>) => Promise<void> }) {
  const [ipPreview, setIpPreview] = useState<Row | null>(null);
  const [ipNote, setIpNote] = useState("");
  const [sheet, setSheet] = useState<Row | null>(null);
  const [directoryNote, setDirectoryNote] = useState("");
  const previewAddresses = async (addresses: string) => {
    const preview = await api.request<Row>("/api/discovery/import-ips", { method: "POST", body: JSON.stringify({ addresses }) });
    setIpPreview(preview);
    setIpNote("");
    onError("");
  };
  return (
    <>
      <section className="card">
        <h2>Import from IP</h2>
        <p className="muted">Paste one address per line, or hostname and address. A .txt or .csv file can fill the same list. These records are imported inventory. They are not probe results and they do not approve a scan.</p>
        <form onSubmit={async (event) => {
          event.preventDefault();
          const addresses = String(new FormData(event.currentTarget).get("addresses") || "");
          try { await previewAddresses(addresses); }
          catch (err) { onError(messageFrom(err)); }
        }}>
          <label>Addresses<textarea name="addresses" placeholder={"10.1.2.3\nLAB-WIN 10.1.2.4"} /></label>
          <div className="row">
            <button className="primary">Preview addresses</button>
            <input type="file" aria-label="Import IP file" accept=".txt,.csv" onChange={async (event) => {
              const file = event.target.files?.[0];
              event.currentTarget.value = "";
              if (!file) return;
              try { await previewAddresses(await file.text()); }
              catch (err) { onError(messageFrom(err)); }
            }} />
          </div>
        </form>
        {ipPreview?.preview_id && (
          <>
            <p>{ipPreview.scope_statement}</p>
            <p>{ipPreview.row_count} {ipPreview.row_count === 1 ? "address" : "addresses"}. Errors: {ipPreview.errors.length}. Duplicates: {ipPreview.duplicates.length}.</p>
            <Table columns={["row", "field", "message"]} rows={ipPreview.errors} />
            <button className="primary" disabled={ipPreview.errors.length > 0} onClick={async () => {
              try {
                await api.request("/api/inventory/commit", { method: "POST", body: JSON.stringify({ preview_id: ipPreview.preview_id, confirm: true, acknowledge_duplicates: ipPreview.duplicates.length > 0 }) });
                const reconciled = await api.request<Row>("/api/reconcile", { method: "POST" });
                setIpNote(`${ipPreview.row_count} imported. Reconcile recorded ${reconciled.assets} identities. No probe was run.`);
                setIpPreview(null);
                onError("");
              } catch (err) { onError(messageFrom(err)); }
            }}>Import these addresses</button>
          </>
        )}
        {ipNote && <p>{ipNote}</p>}
      </section>
      <section className="card">
        <h2>Ship inventory</h2>
        <p className="muted">Spreadsheet addresses propose discovery scope. They do not authorize it. Macros and formulas are not executed.</p>
        <input type="file" aria-label="Ship inventory spreadsheet" accept=".csv,.xlsx" onChange={async (event) => {
          const file = event.target.files?.[0];
          event.currentTarget.value = "";
          if (!file) return;
          const body = new FormData();
          body.append("file", file);
          try { setSheet(await api.request("/api/inventory/preview", { method: "POST", body })); onError(""); }
          catch (err) { onError(err instanceof Error ? err.message : "Preview failed"); }
        }} />
        {sheet?.need_worksheet && (
          <form className="row" onSubmit={async (event) => {
            event.preventDefault();
            const file = (event.currentTarget.elements.namedItem("file") as HTMLInputElement).files?.[0];
            const worksheet = (event.currentTarget.elements.namedItem("worksheet") as HTMLSelectElement).value;
            if (!file) return;
            const body = new FormData();
            body.append("file", file);
            body.append("worksheet", worksheet);
            setSheet(await api.request("/api/inventory/preview", { method: "POST", body }));
          }}>
            <input name="file" type="file" accept=".xlsx" required />
            <select name="worksheet">{sheet.worksheets.map((name: string) => <option key={name}>{name}</option>)}</select>
            <button className="secondary">Preview worksheet</button>
          </form>
        )}
        {sheet?.preview_id && (
          <>
            <p>{sheet.row_count} rows. Errors: {sheet.errors.length}. Duplicates: {sheet.duplicates.length}. Hash <span className="mono">{sheet.sha256}</span></p>
            <Table columns={["row", "field", "message"]} rows={sheet.errors} />
            <button className="primary" onClick={async () => {
              try {
                await api.request("/api/inventory/commit", { method: "POST", body: JSON.stringify({ preview_id: sheet.preview_id, confirm: true, acknowledge_duplicates: sheet.duplicates.length > 0 }) });
                const reconciled = await api.request<Row>("/api/reconcile", { method: "POST" });
                setIpNote(`Spreadsheet imported. Reconcile recorded ${reconciled.assets} identities. No probe was run.`);
                setSheet(null);
                onError("");
              } catch (err) { onError(err instanceof Error ? err.message : "Commit failed"); }
            }}>Confirm import</button>
          </>
        )}
      </section>
      <section className="card">
        <h2>Active Directory</h2>
        <p className="muted">Reads computer objects from the directory this computer is joined to. It uses the current sign-in. No password is stored, and signing stays on. If the directory cannot be read, nothing is invented.</p>
        <button className="primary" onClick={async () => {
          try {
            let body: Row = { job: { status: "" } };
            await onTrack("Scan Active Directory", async () => {
              body = await api.request<Row>("/api/discovery/aduc", { method: "POST" });
            });
            if (body.job?.status !== "completed") {
              onError(body.job?.error || "Active Directory scan did not complete.");
              return;
            }
            const count = body.computers ?? 0;
            setDirectoryNote(`${count} computer ${count === 1 ? "object" : "objects"} recorded. They are in Inventory.`);
            onError("");
          } catch (err) { onError(messageFrom(err)); }
        }}>Scan Active Directory</button>
        {directoryNote && <p>{directoryNote}</p>}
      </section>
    </>
  );
}

function Inventory({ api, onError }: { api: Api; onError: (message: string) => void }) {
  const [body, setBody] = useState<Row>({ assets: [], conflicts: [] });
  const reload = async () => setBody(await api.request("/api/assets"));
  useEffect(() => { void reload().catch((err) => onError(messageFrom(err))); }, []);
  return (
    <section className="card">
      <div className="row">
        <h2>Reconciled identities</h2>
        <button className="primary" onClick={async () => { await api.request("/api/reconcile", { method: "POST" }); await reload(); }}>Reconcile</button>
      </div>
      <p className="muted">Hostname matches stay provisional. Shared addresses are not merged by IP. Switches, printers, appliances, and standalone hosts may have no directory object.</p>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Select</th><th>Name</th><th>Address</th><th>Sources</th><th>Confidence</th><th>Flags</th><th>Decision</th></tr></thead>
          <tbody>
            {body.assets.map((asset: Row) => (
              <tr key={asset.id}>
                <td><input type="checkbox" checked={asset.selected} onChange={async (event) => {
                  try { await api.request(`/api/assets/${asset.id}/selection`, { method: "POST", body: JSON.stringify({ selected: event.target.checked }) }); await reload(); onError(""); }
                  catch (err) { onError(err instanceof Error ? err.message : "Selection blocked"); }
                }} /></td>
                <td>{asset.hostname || asset.display_name}</td>
                <td className="mono">{asset.ip_address}</td>
                <td>{asset.sources.map((source: Row) => <span key={source.ref} className={`chip ${source.evidence_kind}`}>{source.kind}</span>)}</td>
                <td>{asset.identity_confidence}<div className="muted">{asset.match_basis}</div></td>
                <td className="flags">{(asset.flags || []).join(", ")}</td>
                <td>{asset.human_decision || (
                  <button className="secondary" onClick={async () => {
                    const reason = window.prompt("Reason for confirming this identity");
                    if (!reason) return;
                    try { await api.request(`/api/assets/${asset.id}/decision`, { method: "POST", body: JSON.stringify({ decision: "confirm_identity", reason }) }); await reload(); }
                    catch (err) { onError(err instanceof Error ? err.message : "Decision failed"); }
                  }}>Confirm identity</button>
                )}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Baselines({ api, onError, onTrack }: { api: Api; onError: (message: string) => void; onTrack: (label: string, work: () => Promise<void>) => Promise<void> }) {
  const [configs, setConfigs] = useState<Row[]>([]);
  const [assets, setAssets] = useState<Row[]>([]);
  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [note, setNote] = useState("");
  const reload = async () => {
    setConfigs(await api.request("/api/baselines/configs"));
    const inventory = await api.request<Row>("/api/assets");
    setAssets(inventory.assets || []);
  };
  useEffect(() => { void reload().catch((err) => onError(messageFrom(err))); }, []);
  const selected = configs.filter((config) => picked[`${config.kind}:${config.source_id}`]);
  const scanning = assets.filter((asset) => asset.selected);
  const assetName = (asset: Row) => asset.hostname || asset.display_name || asset.id;
  return (
    <>
      <section className="card">
        <h2>Assets in this scan</h2>
        <p className="muted">These are the assets selected in Inventory. The scan reads only this set.</p>
        {scanning.length === 0 && <p>Nothing is selected in Inventory. Choose assets there before scanning.</p>}
        {scanning.length > 0 && (
          <ul className="scan-list">
            {scanning.map((asset) => (
              <li key={asset.id}>
                <strong>{assetName(asset)}</strong>
                <span className="muted"> · {asset.ip_address || "no address"}{asset.os_name ? ` · ${asset.os_name}` : ""}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="card">
        <h2>Choose what to scan</h2>
        <p className="muted">These are the files uploaded on Preparation. Check the ones to look for on the assets above. Findings shows what still needs to be applied.</p>
        {configs.length === 0 && <p className="muted">Nothing is uploaded yet.</p>}
        <ul className="scan-list">
          {configs.map((config) => {
            const key = `${config.kind}:${config.source_id}`;
            return (
              <li key={key}>
                <label className="checkline">
                  <input type="checkbox" checked={Boolean(picked[key])} onChange={() => setPicked((current) => ({ ...current, [key]: !current[key] }))} />
                  <span><strong>{config.label}</strong><span className="muted"> · {config.detail}</span></span>
                </label>
              </li>
            );
          })}
        </ul>
        <button className="primary" disabled={selected.length === 0 || scanning.length === 0} onClick={async () => {
          const names = scanning.map(assetName).join(", ");
          try {
            await onTrack(`Scan ${selected.map((config) => config.label).join(", ")}`, async () => {
              await api.request("/api/scans", { method: "POST", body: JSON.stringify({ items: selected.map((config) => ({ kind: config.kind, source_id: config.source_id })) }) });
            });
            setNote(`Scan recorded for ${names}. Open Findings to see what needs to be applied.`);
            onError("");
          } catch (err) { onError(messageFrom(err)); }
        }}>Scan selected</button>
        {note && <p>{note}</p>}
      </section>
    </>
  );
}

function Findings({ api, onError, onTrack }: { api: Api; onError: (message: string) => void; onTrack: (label: string, work: () => Promise<void>) => Promise<void> }) {
  const [rows, setRows] = useState<Row[]>([]);
  const [scans, setScans] = useState<Row[]>([]);
  const [proposed, setProposed] = useState<Record<string, string>>({});
  const reload = async () => {
    setRows(await api.request("/api/findings"));
    setScans(await api.request("/api/scans"));
  };
  useEffect(() => { void reload().catch((err) => onError(messageFrom(err))); }, []);
  const latest = latestScans(scans);
  const needed = latest.flatMap((row) => (row.assets || []).filter((asset: Row) => asset.presence === "absent").map((asset: Row) => ({ ...asset, scan: row })));
  return (
    <section className="card">
      <div className="row">
        <h2>What needs to be applied</h2>
        <button className="primary" onClick={async () => {
          try {
            await onTrack("Assess selected assets", async () => {
              const assets = await api.request<Row>("/api/assets");
              const asset_ids = assets.assets.filter((asset: Row) => asset.selected).map((asset: Row) => asset.id);
              await api.request("/api/assessments", { method: "POST", body: JSON.stringify({ asset_ids }) });
            });
            await reload();
            onError("");
          } catch (err) { onError(err instanceof Error ? err.message : "Assessment failed"); }
        }}>Assess selected assets</button>
      </div>
      <p className="muted">Already recorded means the lab file lists that uploaded file. Needs to be applied means a selected asset was read and the file was not listed. Not visible means no selected asset had a readable lab file.</p>
      <div className="pies">
        <Pie title="Applied and still needed" slices={scanSlices(latest)} />
        <Pie title="Rule checks" slices={applicationSlices(latestByRule(rows))} />
      </div>
      {latest.length === 0 && <p className="muted">No scan yet. Choose uploaded files on Scan, then come back here.</p>}
      {needed.map((item) => {
        const proposalKey = `${item.scan.id}:${item.asset_id}`;
        const msuRead = item.scan.kind === "msu" ? msuReadStatement(item.scan.observation) : "";
        const canSuggest = item.scan.kind !== "msu" || Boolean(msuRead);
        return (
        <article key={proposalKey} className="card material">
          <p><strong>{item.scan.label}</strong> · {item.hostname || item.asset_id}</p>
          {msuRead && <p className="muted">{msuRead}</p>}
          <p className="muted">Needs to be applied. The imported package was not executed.</p>
          {canSuggest && <button className="secondary" onClick={async () => {
            try {
              await api.request("/api/install-proposals", { method: "POST", body: JSON.stringify({ kind: item.scan.kind, source_id: item.scan.source_id, asset_id: item.asset_id }) });
              onError("");
              setProposed((current) => ({ ...current, [proposalKey]: `Install proposed for ${item.hostname || item.asset_id}.` }));
            } catch (err) { onError(messageFrom(err)); }
          }}>Propose install</button>}
          {proposed[proposalKey] && <p>{proposed[proposalKey]}</p>}
        </article>
        );
      })}
      <div className="table-wrap">
        <table>
          <thead><tr><th>Rule</th><th>Class</th><th>Result</th><th>Evidence</th><th>Observation</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td className="mono">{row.rule_id}</td>
                <td>{row.classification}</td>
                <td>{row.result}</td>
                <td><span className={`chip ${row.evidence_kind}`}>{row.evidence_kind}</span></td>
                <td>{row.observation}{row.risk?.commander ? ` Commander: ${row.risk.commander}` : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Approvals({ api, onError }: { api: Api; onError: (message: string) => void }) {
  const [findings, setFindings] = useState<Row[]>([]);
  const [proposals, setProposals] = useState<Row[]>([]);
  const [approvals, setApprovals] = useState<Row[]>([]);
  const [assets, setAssets] = useState<Row[]>([]);
  const [controller, setController] = useState<Row | null>(null);
  const [note, setNote] = useState("");
  const reload = async () => {
    const [nextFindings, nextProposals, nextApprovals, inventory, boundary] = await Promise.all([
      api.request<Row[]>("/api/findings"),
      api.request<Row[]>("/api/proposals"),
      api.request<Row[]>("/api/approvals"),
      api.request<Row>("/api/assets"),
      api.request<Row>("/api/controller"),
    ]);
    setFindings(nextFindings);
    setProposals(nextProposals);
    setApprovals(nextApprovals);
    setAssets(inventory.assets || []);
    setController(boundary);
  };
  useEffect(() => { void reload().catch((err) => onError(messageFrom(err))); }, []);
  const openFindings = latestFailures(findings);
  const assetName = (asset: Row) => asset.hostname || asset.display_name || asset.id;
  const nameFor = (id: string) => {
    const asset = assets.find((row) => row.id === id);
    return asset ? assetName(asset) : "Asset";
  };
  const selectedAssets = assets.filter((asset) => asset.selected);
  const installs = proposals.filter((proposal) => proposal.action_type === "record_install" && proposal.hash_matches_record !== false && !proposals.some((row) => row.id !== proposal.id && row.asset_id === proposal.asset_id && row.rule_id === proposal.rule_id && row.action_type === proposal.action_type && row.version > proposal.version));
  const rollbacks = proposals.filter((proposal) => proposal.action_type === "rollback" && proposal.hash_matches_record !== false);
  const findingProposals = openFindings
    .map((finding) => currentProposal(proposals, finding.id))
    .filter((proposal): proposal is Row => Boolean(proposal) && proposal.action_type !== "rollback");
  const waiting = [...findingProposals, ...installs, ...rollbacks];
  const earlier = proposals.filter((proposal) => !waiting.some((row) => row.id === proposal.id));
  return (
    <>
      <section className="card">
        <h2>Selected inventory</h2>
        <p className="muted">These are the assets selected in Inventory. A change can be applied only to this set.</p>
        {selectedAssets.length === 0 && <p>Nothing is selected in Inventory.</p>}
        <ul className="scan-list">
          {selectedAssets.map((asset) => (
            <li key={asset.id}>
              <strong>{assetName(asset)}</strong>
              <span className="muted"> · {asset.ip_address || "no address"}{asset.os_name ? ` · ${asset.os_name}` : ""} · {asset.automation_class || "unknown"}</span>
            </li>
          ))}
        </ul>
      </section>
      <section className="card exec">
        <h2>What will be applied</h2>
        {note && <p>{note}</p>}
        <div className="exec-head">
          <span>Asset</span>
          <span>Change</span>
          <span>Approve</span>
        </div>
        {waiting.length === 0 && <p className="muted">No change is waiting. A failed check or an install proposal has to be recorded first.</p>}
        {waiting.map((proposal) => {
          const approval = openApproval(approvals, proposal.id);
          const used = approvals.some((row) => row.proposal_id === proposal.id && row.decision === "approved" && row.used);
          return (
            <article key={proposal.id} className="exec-row">
              <div>
                <strong>{nameFor(proposal.asset_id)}</strong>
              </div>
              <div>
                <strong>{changeTitle(proposal)}</strong>
                <p>{proposal.impact}</p>
              </div>
              <div className="exec-actions">
                {approval && <p>Approved. Execute it from Execution. The file has not changed.</p>}
                {!approval && used && <p>This approval was already used.</p>}
                {!approval && !used && (
                  <>
                    <button className="primary" onClick={async () => {
                      try {
                        await api.request("/api/approvals", { method: "POST", body: JSON.stringify({ proposal_id: proposal.id, decision: "approved" }) });
                        setNote("Approved. The file has not changed. Execute it from Execution.");
                        await reload();
                      } catch (err) { onError(messageFrom(err)); }
                    }}>Approve</button>
                    <button className="danger" onClick={async () => {
                      try { await api.request("/api/approvals", { method: "POST", body: JSON.stringify({ proposal_id: proposal.id, decision: "rejected" }) }); await reload(); onError(""); }
                      catch (err) { onError(messageFrom(err)); }
                    }}>Reject</button>
                  </>
                )}
              </div>
            </article>
          );
        })}
        {openFindings.filter((finding) => !currentProposal(proposals, finding.id)).map((finding) => (
          <article key={finding.id} className="exec-row">
            <div><strong>{nameFor(finding.asset_id)}</strong></div>
            <div>
              <strong>{finding.rule_id}</strong>
              <p>{finding.observation}</p>
            </div>
            <button className="secondary" onClick={async () => {
              try { await api.request("/api/proposals", { method: "POST", body: JSON.stringify({ finding_id: finding.id }) }); await reload(); onError(""); }
              catch (err) { onError(messageFrom(err)); }
            }}>Create proposal</button>
          </article>
        ))}
        {earlier.length > 0 && (
          <details className="fold">
            <summary>{earlier.length} earlier {earlier.length === 1 ? "proposal" : "proposals"}</summary>
            {earlier.map((proposal) => (
              <p key={proposal.id} className="muted">{proposal.rule_id} · version {proposal.version} · {proposal.hash_matches_record === false ? "hash no longer matches" : "replaced or already reviewed"}</p>
            ))}
          </details>
        )}
      </section>
      <section className="card">
        <h2>What might happen</h2>
        <p className="muted">This is what Execution can show if the change is run. Approval itself does not apply it.</p>
        {controller?.scheduling_halted && <p>Scheduling is stopped. A new change will not start. An in-progress installation is not killed.</p>}
        {waiting.length === 0 && <p className="muted">No change is waiting, so nothing would be written.</p>}
        {waiting.map((proposal) => {
          const asset = assets.find((row) => row.id === proposal.asset_id);
          return (
            <article key={proposal.id} className="card material">
              <p><strong>{nameFor(proposal.asset_id)}</strong> · {proposal.rule_id}</p>
              <ul className="scan-list">
                {mightHappen(proposal, asset).map((line) => <li key={line}>{line}</li>)}
              </ul>
            </article>
          );
        })}
      </section>
    </>
  );
}

function mightHappen(proposal: Row, asset: Row | undefined) {
  const lines = [String(proposal.impact || "The recorded impact is empty.")];
  if (proposal.hash_matches_record === false) {
    lines.push("This hash no longer matches the record. Approval and execution both refuse it until the change is proposed again.");
  }
  if (proposal.action_type === "procedure") {
    lines.push("Recording the plan does not change a host. Execution refuses this proposal and leaves the file as it is.");
    return lines;
  }
  if (!asset?.lab_target_path) lines.push("This asset has no lab file. Execution refuses the write.");
  if ((asset?.automation_class || "unknown") !== "approved_noncritical") {
    lines.push("The asset is not classed as approved noncritical. Execution stops before the file changes.");
  }
  const windowName = proposal.change_type === "patch" ? "patch" : proposal.change_type === "stig_config" ? "STIG configuration" : String(proposal.change_type || "matching");
  lines.push(`Without a current ${windowName} maintenance window, execution stops and the file stays unchanged.`);
  lines.push("If the lab file hash no longer matches this proposal, execution stops and reports configuration drift.");
  if (proposal.action_type === "record_install") lines.push("A successful run adds this id to the lab file. The imported package is not run, and a remote operating system is not changed.");
  if (proposal.action_type === "remediate") lines.push("A successful run sets audit_policy in the lab file. It does not change a remote operating system.");
  if (proposal.action_type === "rollback") lines.push("A successful run restores the backup only while the file still matches the recorded hash. A later edit blocks the rollback.");
  if (proposal.expires_at) lines.push(`This proposal expires ${proposal.expires_at}. After that, execution refuses it.`);
  return lines;
}

function latestFailures(findings: Row[]) {
  const ranked = findings.filter((row) => row.result === "fail").sort((a, b) => String(b.collected_at).localeCompare(String(a.collected_at)));
  const seen = new Set<string>();
  return ranked.filter((row) => {
    const key = `${row.asset_id}|${row.rule_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function currentProposal(proposals: Row[], findingId: string) {
  return proposals
    .filter((row) => row.finding_id === findingId && row.hash_matches_record !== false)
    .sort((a, b) => Number(b.version) - Number(a.version))[0];
}

function MaterialBoard({ api, packages, benchmarks, updates, onImported, onError }: { api: Api; packages: Row[]; benchmarks: Row[]; updates: Row[]; onImported: () => Promise<void>; onError: (message: string) => void }) {
  const groups = new Map<string, Row[]>();
  for (const row of benchmarks) groups.set(row.benchmark_id, [...(groups.get(row.benchmark_id) || []), row]);
  const stigs = [...groups.values()].map((versions) => {
    const newest = versions.find((row) => row.version_label === "newest imported version") || versions[versions.length - 1];
    return { newest, earlier: versions.filter((row) => row.id !== newest.id) };
  });
  return (
    <>
      <section className="card">
        <h2>Imported material</h2>
        <p className="muted">A local checksum is not publisher authentication. Imported text is stored and never executed. The version shown for a STIG is the newest imported version, not a latest published version.</p>
        <div className="library">
          <article className="card material">
            <h2>STIG</h2>
            <p className="muted">{stigs.length} {stigs.length === 1 ? "checklist" : "checklists"} · {packages.length} {packages.length === 1 ? "file" : "files"}</p>
            {stigs.map((group) => <p key={group.newest.id}>{group.newest.title}<span className="muted"> · {group.newest.rule_count} rules</span></p>)}
            {stigs.length === 0 && <p className="muted">None imported.</p>}
            <input type="file" aria-label="Upload STIG" accept=".xml,.zip" onChange={async (event) => {
              const file = event.target.files?.[0];
              event.currentTarget.value = "";
              if (!file) return;
              const body = new FormData();
              body.append("file", file);
              try { await api.request("/api/stig/import", { method: "POST", body }); await onImported(); onError(""); }
              catch (err) { onError(messageFrom(err)); }
            }} />
          </article>
          {UPDATE_KINDS.map((kind) => {
            const imported = updates.filter((row) => row.kind === kind.id);
            return (
              <article key={kind.id} className="card material">
                <h2>{kind.label}</h2>
                <p className="muted">{imported.length} imported</p>
                {imported.map((row) => <p key={row.id}>{row.original_filename}</p>)}
                {imported.length === 0 && <p className="muted">None imported.</p>}
                <input type="file" aria-label={`Upload ${kind.label}`} accept=".zip,.xml,.pdf,.json,.csv,.txt,.xlsx,.msu,.cab" onChange={async (event) => {
                  const file = event.target.files?.[0];
                  event.currentTarget.value = "";
                  if (!file) return;
                  const body = new FormData();
                  body.append("kind", kind.id);
                  body.append("file", file);
                  try { await api.request("/api/updates/import", { method: "POST", body }); await onImported(); onError(""); }
                  catch (err) { onError(messageFrom(err)); }
                }} />
              </article>
            );
          })}
        </div>
      </section>
    </>
  );
}


const UPDATE_KINDS = [
  { id: "ecu", label: "ECU" },
  { id: "fam", label: "FAM" },
  { id: "msu", label: "MSU" },
  { id: "iava", label: "IAVA" },
] as const;


function openApproval(approvals: Row[], proposalId: string) {
  return [...approvals].reverse().find((row) => row.proposal_id === proposalId && row.decision === "approved" && !row.used);
}

function Execution({ api, onError, onTrack }: { api: Api; onError: (message: string) => void; onTrack: (label: string, work: () => Promise<void>) => Promise<void> }) {
  const [proposals, setProposals] = useState<Row[]>([]);
  const [approvals, setApprovals] = useState<Row[]>([]);
  const [assets, setAssets] = useState<Row[]>([]);
  const reload = async () => {
    const [nextProposals, nextApprovals, inventory] = await Promise.all([
      api.request<Row[]>("/api/proposals"),
      api.request<Row[]>("/api/approvals"),
      api.request<Row>("/api/assets"),
    ]);
    setProposals(nextProposals);
    setApprovals(nextApprovals);
    setAssets(inventory.assets || []);
  };
  useEffect(() => { void reload().catch((err) => onError(messageFrom(err))); }, []);
  const assetName = (asset: Row) => asset.hostname || asset.display_name || asset.id;
  const current = proposals.filter((proposal) => proposal.hash_matches_record !== false && !proposals.some((row) => row.id !== proposal.id && row.asset_id === proposal.asset_id && row.rule_id === proposal.rule_id && row.action_type === proposal.action_type && row.version > proposal.version));
  const selected = assets.filter((asset) => asset.selected);
  const shown = selected.length ? selected : assets.filter((asset) => current.some((proposal) => proposal.asset_id === asset.id));
  return (
    <section className="card exec">
      <div className="exec-head">
        <span>Asset</span>
        <span>Change</span>
        <span>Decision</span>
      </div>
      {shown.length === 0 && <p className="muted">No asset is selected in Inventory, and no change is waiting.</p>}
      {shown.map((asset) => {
        const changes = current.filter((proposal) => proposal.asset_id === asset.id);
        if (changes.length === 0) {
          return (
            <article key={asset.id} className="exec-row">
              <div>
                <strong>{assetName(asset)}</strong>
                <p className="muted">{asset.ip_address || "no address"}{asset.os_name ? ` · ${asset.os_name}` : ""}</p>
              </div>
              <p className="muted">No change is waiting for this asset.</p>
              <span />
            </article>
          );
        }
        return changes.map((proposal) => {
          const approval = openApproval(approvals, proposal.id);
          const used = approvals.some((row) => row.proposal_id === proposal.id && row.decision === "approved" && row.used);
          return (
            <article key={proposal.id} className="exec-row">
              <div>
                <strong>{assetName(asset)}</strong>
                <p className="muted">{asset.ip_address || "no address"}{asset.os_name ? ` · ${asset.os_name}` : ""}</p>
              </div>
              <div>
                <strong>{changeTitle(proposal)}</strong>
                <p>{proposal.impact}</p>
              </div>
              <div className="exec-actions">
                {approval && proposal.action_type === "procedure" && (
                  <button className="primary" onClick={async () => {
                    try {
                      await onTrack(`Record plan for ${assetName(asset)}`, async () => {
                        await api.request("/api/plans/record", { method: "POST", body: JSON.stringify({ proposal_id: proposal.id, approval_id: approval.id }) });
                      });
                      await reload();
                      onError("");
                    } catch (err) { onError(messageFrom(err)); }
                  }}>Record plan</button>
                )}
                {approval && proposal.action_type !== "procedure" && (
                  <button className="primary" onClick={async () => {
                    try {
                      await onTrack(`Execute ${changeTitle(proposal)} on ${assetName(asset)}`, async () => {
                        await api.request("/api/executions", { method: "POST", body: JSON.stringify({ proposal_id: proposal.id, approval_id: approval.id }) });
                      });
                      await reload();
                      onError("");
                    } catch (err) { onError(messageFrom(err)); }
                  }}>Execute</button>
                )}
                {!approval && used && <p>Already used. The file was not changed again.</p>}
                {!approval && !used && (
                  <button className="secondary" onClick={async () => {
                    try {
                      await api.request("/api/approvals", { method: "POST", body: JSON.stringify({ proposal_id: proposal.id, decision: "approved" }) });
                      await reload();
                      onError("");
                    } catch (err) { onError(messageFrom(err)); }
                  }}>Approve</button>
                )}
              </div>
            </article>
          );
        });
      })}
    </section>
  );
}

function changeTitle(proposal: Row) {
  if (proposal.action_type === "record_install") return "Record install";
  if (proposal.action_type === "remediate") return "STIG configuration";
  if (proposal.action_type === "rollback") return "Rollback";
  if (proposal.action_type === "procedure") return "Manual plan";
  return String(proposal.action_type || "Change");
}

function Jobs({ api, onError, live }: { api: Api; onError: (message: string) => void; live: Row[] }) {
  const [recorded, setRecorded] = useState<Row[]>([]);
  const reload = async () => {
    const [discovery, scans] = await Promise.all([
      api.request<Row[]>("/api/discovery/jobs"),
      api.request<Row[]>("/api/scans"),
    ]);
    setRecorded([
      ...discovery.map((job) => ({ id: job.id, label: `Discovery ${job.kind}`, status: job.status, detail: job.error || job.finished_at || "" })),
      ...scans.map((scan) => ({ id: scan.id, label: scan.label || "Scan", status: "completed", detail: scan.observation || scan.status })),
    ]);
  };
  useEffect(() => {
    void reload().catch((err) => onError(messageFrom(err)));
    const timer = window.setInterval(() => { void reload().catch(() => undefined); }, 2000);
    return () => window.clearInterval(timer);
  }, []);
  const rows = [...live, ...recorded];
  return (
    <section className="card">
      <h2>Running jobs</h2>
      {rows.length === 0 && <p className="muted">Nothing is running. A scan or an assessment will show here.</p>}
      {rows.map((job) => (
        <article key={job.id} className="job">
          <div className="row">
            <strong>{job.label}</strong>
            <span className={job.status === "failed" ? "chip gap" : "chip real"}>{job.status}</span>
          </div>
          <JobBar status={String(job.status)} />
          {job.detail && <p className="muted">{job.detail}</p>}
        </article>
      ))}
    </section>
  );
}

function JobBar({ status }: { status: string }) {
  const running = status === "running";
  const done = status === "completed";
  return (
    <div className="job-track" role="progressbar" aria-label={running ? "Working" : status} aria-busy={running} aria-valuemin={0} aria-valuemax={100} aria-valuenow={running ? undefined : done ? 100 : 0}>
      <div className={running ? "job-fill running" : done ? "job-fill done" : "job-fill stopped"} />
    </div>
  );
}

function Audit({ api, onError }: { api: Api; onError: (message: string) => void }) {
  const [chain, setChain] = useState<Row | null>(null);
  const [events, setEvents] = useState<Row[]>([]);
  const [runs, setRuns] = useState<Row[]>([]);
  const [summary, setSummary] = useState<Row | null>(null);
  const [rollbackNote, setRollbackNote] = useState("");
  const reload = async () => {
    setChain(await api.request("/api/audit/verify"));
    setEvents(await api.request("/api/audit"));
    setRuns(await api.request("/api/executions"));
    setSummary(await api.request("/api/reports/summary"));
  };
  useEffect(() => { void reload().catch((err) => onError(messageFrom(err))); }, []);
  const finished = runs.filter((run) => (run.status === "verified_success" || run.status === "verified_failure") && (run.action_type === "remediate" || run.action_type === "record_install"));
  const assets = summary?.selected_assets || [];
  const counts = summary?.finding_counts || {};
  return (
    <>
      <section className="card">
        <h2>What was recorded</h2>
        <p className="muted">{summary?.statement}</p>
        <div className="counts">
          <div><strong>{assets.length}</strong><span>Selected assets</span></div>
          <div><strong>{summary?.scans?.length || 0}</strong><span>Scans</span></div>
          <div><strong>{summary?.findings || 0}</strong><span>Findings</span></div>
          <div><strong>{summary?.executions?.length || 0}</strong><span>Changes run</span></div>
          <div><strong>{summary?.discovery_jobs?.length || 0}</strong><span>Discovery jobs</span></div>
        </div>
        <p className="muted">Not checked {counts.not_reviewed || 0} · Needs to be applied {counts.fail || 0} · Applied {counts.pass || 0}</p>
        <div className="row">
          <button className="primary" onClick={() => download(api, "/api/reports/summary", "cyber-sentinel-summary.json")}>Export summary</button>
          {assets.map((asset: Row) => (
            <button key={asset.id} className="secondary" onClick={() => download(api, `/api/reports/checklist.ckl?asset_id=${encodeURIComponent(asset.id)}`, `${asset.hostname || "asset"}-checklist.ckl`)}>
              Export checklist · {asset.hostname || asset.display_name}
            </button>
          ))}
          <button className="secondary" onClick={async () => download(api, "/api/reports/findings.csv", "findings.csv")}>Findings CSV</button>
          <button className="secondary" onClick={async () => download(api, "/api/reports/inventory.csv", "inventory.csv")}>Inventory CSV</button>
        </div>
        {assets.length === 0 && <p className="muted">Select an asset in Inventory to export its checklist.</p>}
      </section>
      <section className="card">
        <h2>Record check</h2>
        <p>{chain?.ok ? "Chain verifies." : "Chain does not verify."} {chain?.statement}</p>
        <div className="row">
          <button className="secondary" onClick={() => void reload()}>Verify</button>
          <button className="secondary" onClick={async () => { const body = await api.request("/api/audit/checkpoint", { method: "POST" }); onError(`Checkpoint ${body && (body as Row).signature_status}`); }}>Export checkpoint</button>
          <button className="secondary" onClick={async () => { await api.request("/api/sync/enqueue", { method: "POST" }); const result = await api.request<Row>("/api/sync/deliver-local", { method: "POST" }); onError(`Local inbox stored ${result.acked} records. Executed: ${result.executed}.`); }}>Queue and deliver locally</button>
        </div>
      </section>
      <section className="card">
        <h2>Rollback a finished change</h2>
        <p className="muted">This proposes restoring the backed-up lab file. The file stays as it is until that proposal is approved and run from Execution. Stop and restore are different actions.</p>
        {finished.length === 0 && <p className="muted">No finished lab change to roll back.</p>}
        {finished.map((run) => (
          <div key={run.id} className="row">
            <span className="chip real">{run.status}</span>
            <span>{run.action_type}</span>
            <span className="muted">{run.started_at}</span>
            <button className="danger" onClick={async () => {
              try {
                await api.request("/api/rollbacks", { method: "POST", body: JSON.stringify({ execution_id: run.id }) });
                setRollbackNote("Rollback proposed. Approve that hash, then run it from Execution. The lab file was not restored.");
                await reload();
                onError("");
              } catch (err) { onError(messageFrom(err)); }
            }}>Propose rollback</button>
          </div>
        ))}
        {rollbackNote && <p>{rollbackNote}</p>}
      </section>
      <section className="card">
        <Table columns={["created_at", "actor", "action", "outcome", "object_id"]} rows={events} />
      </section>
    </>
  );
}

function latestScans(rows: Row[]) {
  const seen = new Set<string>();
  return [...rows].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).filter((row) => {
    const key = `${row.kind}:${row.source_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function latestByRule(rows: Row[]) {
  const ranked = [...rows].sort((a, b) => String(b.collected_at).localeCompare(String(a.collected_at)));
  const seen = new Set<string>();
  return ranked.filter((row) => {
    const key = `${row.asset_id}|${row.rule_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function msuReadStatement(observation: unknown) {
  const match = String(observation || "").match(/MSU read:.*?The package was not executed\./);
  return match ? match[0] : "";
}

function scanSlices(results: Row[]) {
  const groups = [
    { label: "Needs to be applied", value: 0, color: "#8d2f39" },
    { label: "Already recorded", value: 0, color: "#0f6b4c" },
    { label: "Not visible", value: 0, color: "#c4a15a" },
  ];
  for (const row of results) {
    const assets = row.assets || [];
    if (assets.length === 0) groups[2].value += 1;
    for (const asset of assets) {
      if (asset.presence === "absent") groups[0].value += 1;
      else if (asset.presence === "present") groups[1].value += 1;
      else groups[2].value += 1;
    }
  }
  return groups.filter((slice) => slice.value > 0);
}

function applicationSlices(rows: Row[]) {
  const groups = [
    { label: "Applied", value: 0, color: "#0f6b4c" },
    { label: "Needs to be applied", value: 0, color: "#8d2f39" },
    { label: "Not checked", value: 0, color: "#c4a15a" },
  ];
  for (const row of rows) {
    if (row.result === "pass") groups[0].value += 1;
    else if (row.result === "fail") groups[1].value += 1;
    else groups[2].value += 1;
  }
  return groups.filter((slice) => slice.value > 0);
}

function Pie({ title, slices }: { title: string; slices: { label: string; value: number; color: string }[] }) {
  const drawn = slices.filter((slice) => slice.value > 0);
  const total = drawn.reduce((sum, slice) => sum + slice.value, 0);
  if (!total) return null;
  let cursor = -Math.PI / 2;
  const arcs = drawn.map((slice) => {
    const sweep = (slice.value / total) * Math.PI * 2;
    const start = cursor;
    cursor += sweep;
    const radius = 42;
    const point = (angle: number) => `${50 + radius * Math.cos(angle)} ${50 + radius * Math.sin(angle)}`;
    return { ...slice, sweep, path: `M 50 50 L ${point(start)} A ${radius} ${radius} 0 ${sweep > Math.PI ? 1 : 0} 1 ${point(cursor)} Z` };
  });
  const summary = drawn.map((slice) => `${slice.label} ${slice.value}`).join(", ");
  return (
    <figure className="pie">
      <figcaption>{title}</figcaption>
      <svg viewBox="0 0 100 100" role="img" aria-label={`${title}. ${summary}. Total ${total}.`}>
        {arcs.length === 1 ? <circle cx="50" cy="50" r="42" fill={arcs[0].color} /> : arcs.map((arc) => <path key={arc.label} d={arc.path} fill={arc.color} />)}
      </svg>
      <ul>
        {drawn.map((slice) => (
          <li key={slice.label}><i style={{ background: slice.color }} />{slice.label} <strong>{slice.value}</strong></li>
        ))}
      </ul>
    </figure>
  );
}

function Table({ columns, rows }: { columns: string[]; rows: Row[] }) {
  if (!rows.length) return <p className="muted">Nothing here yet.</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={row.id || row.event_id || index}>
              {columns.map((column) => <td key={column}>{formatCell(row[column])}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatCell(value: unknown) {
  if (value == null) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

async function download(api: Api, path: string, filename: string) {
  const text = await api.text(path);
  const blob = new Blob([typeof text === "string" ? text : JSON.stringify(text)], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
