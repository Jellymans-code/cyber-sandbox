"use client";

import { FormEvent, useState } from "react";

type StaticAnalysis = {
  size_bytes: number;
  file_type: string;
  entropy: number;
  is_high_entropy: boolean;
  extracted_strings: string[];
  network_indicators: {
    ips: string[];
    urls: string[];
  };
  suspicious_keywords: string[];
};

type ProcessNode = {
  pid: number;
  ppid: number;
  command: string;
  argv: string[];
  timestamp: number;
  children: ProcessNode[];
};

type AnalysisResult = {
  filename: string;
  sha256: string;
  static_analysis: StaticAnalysis;
  processes_observed: number;
  commands_executed: string[];
  process_tree: ProcessNode[];
  risk_assessment: RiskAssessment;
};

type RiskAssessment = {
  verdict: "low_risk" | "suspicious" | "high_risk";
  score: number;
  reasons: string[];
};

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

function ProcessTree({
  node,
  depth = 0,
}: {
  node: ProcessNode;
  depth?: number;
}) {
  return (
    <div
      className="border-l border-slate-700 pl-4"
      style={{ marginLeft: `${depth * 12}px` }}
    >
      <div className="my-2 flex flex-wrap items-center gap-3">
        <span className="rounded bg-blue-500/10 px-2 py-1 font-mono text-xs text-blue-400">
          PID {node.pid}
        </span>

        <span className="break-all font-mono text-sm text-slate-300">
          {node.command}{" "}
          {node.argv.length > 0 ? node.argv.join(" ") : ""}
        </span>
      </div>

      {node.children.map((child, index) => (
        <ProcessTree
          key={`${child.pid}-${index}`}
          node={child}
          depth={depth + 1}
        />
      ))}
    </div>
  );
}

export default function SandboxDashboard() {
  const [file, setFile] = useState<File | null>(null);
  const [results, setResults] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!file) {
      setError("Please select a file first.");
      return;
    }

    setLoading(true);
    setError("");
    setResults(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        let message = "Analysis failed.";

        try {
          const body = await response.json();
          message = body.detail ?? message;
        } catch {
          // Keep generic error message.
        }

        throw new Error(message);
      }

      const data: AnalysisResult = await response.json();
      setResults(data);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to connect to the sandbox API."
      );
    } finally {
      setLoading(false);
    }
  }

  const staticAnalysis = results?.static_analysis;

  return (
    <main className="min-h-screen bg-slate-950 px-4 py-8 text-slate-100 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-6xl">
        {/* Header */}
        <header className="mb-8">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-green-400" />
            <span className="text-xs font-medium uppercase tracking-wider text-green-400">
              Sandbox Online
            </span>
          </div>

          <h1 className="mt-3 text-3xl font-bold tracking-tight text-white">
            eBPF Sandbox Analyzer
          </h1>

          <p className="mt-2 text-sm text-slate-400">
            Static file analysis and runtime process telemetry in an isolated
            container.
          </p>
        </header>

        {/* Upload */}
        <form
          onSubmit={handleUpload}
          className="mb-6 rounded-xl border border-slate-800 bg-slate-900 p-6"
        >
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
            <input
              type="file"
              onChange={(event) => {
                setFile(event.target.files?.[0] ?? null);
                setError("");
              }}
              className="block w-full cursor-pointer text-sm text-slate-400
                file:mr-4 file:rounded-md file:border-0
                file:bg-blue-600 file:px-4 file:py-2
                file:text-sm file:font-medium file:text-white
                hover:file:bg-blue-700"
            />

            <button
              type="submit"
              disabled={!file || loading}
              className="rounded-md bg-blue-600 px-6 py-2.5 font-medium text-white
                transition hover:bg-blue-700
                disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Analyzing..." : "Analyze File"}
            </button>
          </div>

          {file && (
            <p className="mt-3 text-sm text-slate-500">
              Selected:{" "}
              <span className="font-mono text-slate-300">{file.name}</span>
            </p>
          )}
        </form>

        {/* Error */}
        {error && (
          <div className="mb-6 rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="mb-6 rounded-xl border border-blue-900/50 bg-blue-950/20 p-5">
            <div className="flex items-center gap-3">
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-blue-400" />
              <div>
                <p className="font-medium text-blue-300">
                  Analyzing sample...
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  Running static analysis and collecting eBPF events.
                </p>
              </div>
            </div>
          </div>
        )}

        {results && staticAnalysis && (
          <div className="space-y-6">
          <div className={`mb-6 rounded-xl border p-5 ${
            results.risk_assessment.verdict === "high_risk"
              ? "border-red-800 bg-red-950/40"
              : results.risk_assessment.verdict === "suspicious"
              ? "border-yellow-800 bg-yellow-950/40"
              : "border-green-800 bg-green-950/40"
          }`}>
            <p className="text-xs font-medium uppercase tracking-wider text-slate-400">Verdict</p>
            <p className="mt-1 text-xl font-semibold text-white">
              {results.risk_assessment.verdict.replace("_", " ")}
            </p>
            <ul className="mt-3 list-inside list-disc space-y-1 text-sm text-slate-300">
              {results.risk_assessment.reasons.map((reason, i) => (
                <li key={i}>{reason}</li>
              ))}
            </ul>
          </div>
            {/* Overview cards */}
            <section className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
                <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
                  SHA-256
                </p>

                <p className="mt-3 break-all font-mono text-xs leading-5 text-slate-300">
                  {results.sha256}
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
                <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
                  File
                </p>

                <p className="mt-3 font-medium text-white">
                  {staticAnalysis.file_type}
                </p>

                <p className="mt-1 text-sm text-slate-500">
                  {staticAnalysis.size_bytes.toLocaleString()} bytes
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
                <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
                  Shannon Entropy
                </p>

                <div className="mt-3 flex items-center gap-3">
                  <span className="text-2xl font-semibold text-white">
                    {staticAnalysis.entropy.toFixed(2)}
                  </span>

                  {staticAnalysis.is_high_entropy && (
                    <span className="rounded bg-yellow-900/40 px-2 py-1 text-xs text-yellow-400">
                      High
                    </span>
                  )}
                </div>

                <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className="h-full rounded-full bg-blue-500"
                    style={{
                      width: `${Math.min(
                        (staticAnalysis.entropy / 8) * 100,
                        100
                      )}%`,
                    }}
                  />
                </div>
              </div>
            </section>

            {/* Static analysis */}
            <section className="rounded-xl border border-slate-800 bg-slate-900">
              <div className="border-b border-slate-800 px-6 py-4">
                <h2 className="font-semibold text-white">
                  Static Indicators
                </h2>

                <p className="mt-1 text-xs text-slate-500">
                  Indicators discovered without executing the sample.
                </p>
              </div>

              <div className="grid grid-cols-1 gap-8 p-6 md:grid-cols-2">
                {/* Network */}
                <div>
                  <h3 className="mb-3 text-sm font-medium text-slate-400">
                    Network Artifacts
                  </h3>

                  {staticAnalysis.network_indicators.urls.length > 0 ||
                  staticAnalysis.network_indicators.ips.length > 0 ? (
                    <div className="space-y-2">
                      {staticAnalysis.network_indicators.urls.map((url) => (
                        <div
                          key={url}
                          className="break-all rounded-md bg-slate-950 px-3 py-2 font-mono text-xs text-blue-400"
                        >
                          {url}
                        </div>
                      ))}

                      {staticAnalysis.network_indicators.ips.map((ip) => (
                        <div
                          key={ip}
                          className="rounded-md bg-slate-950 px-3 py-2 font-mono text-xs text-blue-400"
                        >
                          {ip}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-slate-600">
                      None detected.
                    </p>
                  )}
                </div>

                {/* Suspicious strings */}
                <div>
                  <h3 className="mb-3 text-sm font-medium text-slate-400">
                    Suspicious Strings
                  </h3>

                  {staticAnalysis.suspicious_keywords.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {staticAnalysis.suspicious_keywords.map((keyword) => (
                        <span
                          key={keyword}
                          className="rounded border border-yellow-800/60 bg-yellow-900/20 px-2.5 py-1 font-mono text-xs text-yellow-400"
                        >
                          {keyword}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-slate-600">
                      None detected.
                    </p>
                  )}
                </div>
              </div>
            </section>

            {/* Process tree */}
            <section className="rounded-xl border border-slate-800 bg-slate-900">
              <div className="flex flex-col gap-2 border-b border-slate-800 px-6 py-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="font-semibold text-white">
                    Execution Process Tree
                  </h2>

                  <p className="mt-1 text-xs text-slate-500">
                    Runtime process activity captured by eBPF.
                  </p>
                </div>

                <span className="text-xs text-slate-500">
                  {results.processes_observed} processes observed
                </span>
              </div>

              <div className="overflow-x-auto p-6">
                <div className="min-w-[600px] rounded-lg border border-slate-800 bg-slate-950 p-4">
                  {results.process_tree.length > 0 ? (
                    results.process_tree.map((root, index) => (
                      <ProcessTree
                        key={`${root.pid}-${index}`}
                        node={root}
                      />
                    ))
                  ) : (
                    <p className="text-sm text-slate-600">
                      No execution activity detected.
                    </p>
                  )}
                </div>
              </div>
            </section>

            {/* Commands */}
            <section className="rounded-xl border border-slate-800 bg-slate-900 p-6">
              <div className="mb-4">
                <h2 className="font-semibold text-white">
                  Commands Observed
                </h2>

                <p className="mt-1 text-xs text-slate-500">
                  Executables observed during runtime.
                </p>
              </div>

              {results.commands_executed.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {results.commands_executed.map((command, index) => (
                    <span
                      key={`${command}-${index}`}
                      className="rounded-md bg-slate-800 px-3 py-1.5 font-mono text-xs text-slate-300"
                    >
                      {command}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-600">
                  No commands were captured.
                </p>
              )}
            </section>
          </div>
        )}
      </div>
    </main>
  );
}
