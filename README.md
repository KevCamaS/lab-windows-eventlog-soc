# Lab SOC T1 — Logs Windows (Event ID 4624 / 4625)

Practiqué análisis de logons de Windows como lo haría un analista Tier 1: separar ruido de un posible brute force, sacar IoCs y decidir si escalo.

Trabajé con un extracto estilo Event Viewer (CSV). No es un DC real; el objetivo fue entrenar el ojo para **4625** (fallo), **4624** (éxito) y el Logon Type (3 = red, 10 = RDP).

## Por qué lo hice
En el perfil del puesto piden análisis de logs Windows e IoCs. Ya tenía práctica en Linux (auth/SSH + Fail2ban en AWS). Quería cubrir el lado Windows sin inventar “experiencia en AD”.

## Qué salió al correrlo
- Varios 4625 desde `203.0.113.88` por RDP (Type 10) → lo marqué como fuerza bruta (**T1110**), prioridad alta.
- Fallos internos de `j.perez` desde `10.0.1.55` seguidos de un 4624 → revisar si fue typo o spray; no cerrar a ciegas.
- Login local de usuario conocido → bajo ruido.

## Cómo ejecutar
```bash
python scripts/analizar_eventos.py
```
Genera `resultados/triage_windows.json`.

## Relación con otras prácticas
- Fail2ban (AWS): misma idea T1110, otro SO.
- TryHackMe Hydra: vi el ataque; acá practico la **detección** en logs.

Kevin Cama — github.com/KevCamaS
