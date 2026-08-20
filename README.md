# Lab SOC T1 — Análisis de logs Windows (Event ID 4624 / 4625)

Laboratorio básico de **SOC Tier 1**: parsear eventos de inicio de sesión de Windows, extraer **IoCs**, clasificar y mapear a **MITRE ATT&CK**.

No requiere un Active Directory real. Usa un CSV sintético estilo Event Viewer.

## Qué cubre del puesto
- Análisis de logs **Windows**
- IoCs (usuario, IP, workstation, Event ID)
- Triage / posible falso positivo
- MITRE **T1110** (brute force) y **T1078** (valid accounts)

## Cómo ejecutar
```bash
python scripts/analizar_eventos.py
```

## Interpretación rápida
| Event ID | Significado |
|----------|-------------|
| 4625 | Logon **fallido** |
| 4624 | Logon **exitoso** |
| Logon Type 3 | Red (no consola local) |
| Logon Type 10 | Remote Desktop |

Autor: Kevin Anthony Cama Sánchez — github.com/KevCamaS
