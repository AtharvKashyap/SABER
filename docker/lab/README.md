# SABER Vulnerable Lab

Authorized local testing only. These targets are intentionally insecure — never
expose them to an untrusted network.

## Targets (on the `saber-lab` bridge network)

| Service | Reach as | Notes |
|---------|----------|-------|
| DVWA | `dvwa` | Classic vulnerable web app |
| Juice Shop | `juiceshop` (port 3000) | Modern SPA |
| Metasploitable2 | `metasploitable` | Multi-service box (SSH/SMB/FTP/web) |
| vulnbin | `vulnbin` (port 9001) | Custom overflow binary + `/flag.txt` |

## Use

```bash
make lab-up      # build vulnbin, create the saber-lab network, start targets, write runs/lab_scope.yaml
make lab-down    # stop and remove everything
```

Set `SABER_DOCKER_NETWORK=saber-lab` in `.env` before launching SABER so tool
containers can resolve the target names above. Run missions with the generated
scope: `--scope runs/lab_scope.yaml`.
