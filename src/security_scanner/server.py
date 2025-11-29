#!/usr/bin/env python3
"""
Security Scanner MCP Server - Nuclei vulnerability scanning integration
Provides automated security scanning capabilities with cluster distribution
"""

import asyncio
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastmcp import FastMCP

# Server configuration
NUCLEI_BIN = os.path.expanduser("~/go/bin/nuclei")
SCAN_RESULTS_DIR = Path(os.path.join(os.environ.get("AGENTIC_SYSTEM_PATH", "/mnt/agentic-system"), "security-scans"))
SCAN_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Cluster nodes - loaded from environment or config file
def _load_cluster_nodes() -> dict:
    """
    Load cluster node configuration from environment variable.

    Set CLUSTER_NODES_JSON env var with JSON like:
    {"node1": "10.0.0.1", "node2": "10.0.0.2"}
    """
    import json
    env_config = os.environ.get("CLUSTER_NODES_JSON")
    if env_config:
        try:
            return json.loads(env_config)
        except json.JSONDecodeError:
            pass
    return {}

CLUSTER_NODES = _load_cluster_nodes()

# Initialize FastMCP server
mcp = FastMCP("security-scanner")


@mcp.tool()
async def scan_target(
    target: str,
    severity: Optional[str] = "medium,high,critical",
    rate_limit: int = 150,
    timeout: int = 300
) -> str:
    """
    Scan a target URL or IP with Nuclei vulnerability scanner.

    Args:
        target: Target URL or IP address to scan
        severity: Comma-separated severity levels (info, low, medium, high, critical)
        rate_limit: Requests per second (default: 150)
        timeout: Scan timeout in seconds (default: 300)

    Returns:
        JSON string with scan results
    """
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(target) % 10000}"
    output_file = SCAN_RESULTS_DIR / f"{scan_id}.jsonl"

    cmd = [
        NUCLEI_BIN,
        "-target", target,
        "-json",
        "-severity", severity,
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout),
        "-o", str(output_file)
    ]

    start_time = datetime.now()

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        await asyncio.wait_for(process.communicate(), timeout=timeout + 30)

        duration = (datetime.now() - start_time).total_seconds()

        findings = []
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        findings.append(json.loads(line))

        severity_counts = {}
        for finding in findings:
            sev = finding.get("info", {}).get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        metadata = {
            "scan_id": scan_id,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "output_file": str(output_file)
        }

        metadata_file = SCAN_RESULTS_DIR / f"{scan_id}_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        result = {
            "success": True,
            "scan_id": scan_id,
            "target": target,
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "duration_seconds": int(duration),
            "findings_preview": findings[:10],
            "output_file": str(output_file)
        }

        return json.dumps(result, indent=2)

    except asyncio.TimeoutError:
        return json.dumps({"success": False, "error": f"Scan timed out after {timeout} seconds"})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
async def scan_cluster_nodes(
    scan_type: str = "comprehensive",
    severity: str = "medium,high,critical"
) -> str:
    """
    Scan all nodes in the agentic cluster for vulnerabilities.

    Args:
        scan_type: Type of scan - "quick", "comprehensive", "full", "web", or "api"
        severity: Comma-separated severity levels to check

    Returns:
        JSON string with cluster scan results
    """
    results = []

    for node_name, node_ip in CLUSTER_NODES.items():
        result = await scan_target(node_ip, severity)
        result_data = json.loads(result)
        result_data["node_name"] = node_name
        results.append(result_data)

    total_findings = sum(r.get("total_findings", 0) for r in results)

    summary = {
        "cluster_scan_completed": True,
        "nodes_scanned": len(CLUSTER_NODES),
        "total_findings": total_findings,
        "scan_results": results,
        "timestamp": datetime.now().isoformat()
    }

    return json.dumps(summary, indent=2)


@mcp.tool()
async def list_templates(
    tag: Optional[str] = None,
    severity: Optional[str] = None
) -> str:
    """
    List available Nuclei templates by tag or severity.

    Args:
        tag: Filter by tag (e.g., cve, exposure, misconfiguration)
        severity: Filter by severity (info, low, medium, high, critical)

    Returns:
        JSON string with template list
    """
    cmd = [NUCLEI_BIN, "-tl"]

    if tag:
        cmd.extend(["-tags", tag])
    if severity:
        cmd.extend(["-severity", severity])

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()

        templates = [t.strip() for t in stdout.decode().strip().split('\n') if t.strip()]

        return json.dumps({
            "success": True,
            "total_templates": len(templates),
            "templates": templates[:200],
            "filters": {"tag": tag, "severity": severity}
        }, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
async def update_templates() -> str:
    """
    Update Nuclei templates to latest version.

    Returns:
        JSON string with update result
    """
    try:
        process = await asyncio.create_subprocess_exec(
            NUCLEI_BIN, "-update-templates",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()

        return json.dumps({
            "success": True,
            "output": stdout.decode().strip()
        }, indent=2)
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
async def get_scan_results(
    scan_id: str,
    limit: int = 100
) -> str:
    """
    Retrieve results from a previous scan.

    Args:
        scan_id: Scan ID to retrieve
        limit: Maximum number of results to return (default: 100)

    Returns:
        JSON string with scan results
    """
    result_file = SCAN_RESULTS_DIR / f"{scan_id}.jsonl"
    metadata_file = SCAN_RESULTS_DIR / f"{scan_id}_metadata.json"

    if not result_file.exists():
        return json.dumps({"success": False, "error": "Scan not found"})

    results = []
    with open(result_file, 'r') as f:
        for line in f:
            if line.strip():
                results.append(json.loads(line))
                if len(results) >= limit:
                    break

    metadata = {}
    if metadata_file.exists():
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)

    return json.dumps({
        "success": True,
        "scan_id": scan_id,
        "metadata": metadata,
        "findings": results,
        "total_returned": len(results)
    }, indent=2)


@mcp.tool()
async def list_scans(limit: int = 50) -> str:
    """
    List all previous security scans.

    Args:
        limit: Maximum number of scans to return (default: 50)

    Returns:
        JSON string with scan list
    """
    metadata_files = sorted(
        SCAN_RESULTS_DIR.glob("*_metadata.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    scans = []
    for metadata_file in metadata_files[:limit]:
        with open(metadata_file, 'r') as f:
            scans.append(json.load(f))

    return json.dumps({
        "success": True,
        "total_scans": len(scans),
        "scans": scans
    }, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")
