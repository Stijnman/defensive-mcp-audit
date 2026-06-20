from defensive_mcp_audit import BaseAuditPlugin
from typing import Dict, Any, List

class DockerSocketExposurePlugin(BaseAuditPlugin):
    """
    Example plugin: Checks if any discovered service looks like it might be
    exposing a Docker daemon (e.g., on port 2375 or 2376) to non-localhost.
    """
    def audit(self, report: Dict[str, Any], services: List[Dict[str, Any]]) -> None:
        docker_ports = {2375, 2376}
        exposed_docker = []

        for svc in services:
            if svc["port"] in docker_ports:
                addr = svc["address"].strip("[]")
                if addr in ("0.0.0.0", "::", "*") or not addr.startswith("127."):
                    exposed_docker.append(svc)
        
        if exposed_docker:
            # Add to the risk score
            report["risk_score"] += 50
            
            # Append a new finding
            report["findings"].append({
                "id": "DOCKER_SOCKET_EXPOSED",
                "category": "Plugins - Example",
                "severity": "critical",
                "title": "Exposed Docker API detected",
                "value": [f"{s['address']}:{s['port']}" for s in exposed_docker],
                "note": "A service is listening on standard Docker API ports on a non-localhost interface. This allows unauthenticated root-level host compromise."
            })
            
            # Add recommendations
            report["recommendations"].append(
                "Disable exposed Docker sockets or enforce mTLS authentication immediately."
            )
