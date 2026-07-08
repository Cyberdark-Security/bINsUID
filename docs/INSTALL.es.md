# Guía de instalación

bINsUID funciona en **Linux**. Elige el método según tu entorno.

## Requisitos

| Componente | ¿Obligatorio? | Si no está |
|------------|---------------|------------|
| Linux + bash | Sí | No se puede ejecutar |
| `find` | Sí | Falla el escaneo |
| curl o wget | Para instalar online | Copia manual del script o `.deb` |
| Python 3.9+ | Para CLI completa | Solo escáner bash (`binsuid-scan.sh`) |
| getcap (`libcap2-bin`) | No | No escanea capabilities (aviso) |
| sudo sin contraseña | No | Escaneo sudo limitado (aviso) |

---

## Kali Linux

### Desde repositorios (cuando esté empaquetado)

```bash
sudo apt update
sudo apt install binsuid
binsuid --version
```

### pipx (última versión desde git)

```bash
sudo apt install -y pipx
pipx ensurepath
# nueva terminal
pipx install https://github.com/Cyberdark-Security/bINsUID.git
binsuid --scan-only
```

### Desde `.deb` de Releases

```bash
sudo dpkg -i binsuid_*_all.deb
sudo apt -f install
```

---

## Debian / Ubuntu

Igual que Kali: paquete `.deb`, `pipx` o instalador universal.

En sistemas con PEP 668, usa `pipx` o el script `get-binsuid.sh`.

---

## Cualquier Linux (instalador universal)

```bash
curl -fsSL https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/get-binsuid.sh | bash
source ~/.bashrc
binsuid --scan-only
```

Actualizar:

```bash
binsuid --upgrade
```

---

## Objetivos mínimos (sin Python)

Descarga el escáner bash en un equipo con red, transfiérelo al objetivo y ejecuta:

```bash
bash binsuid-scan.sh --quick
```

Tras el escaneo: **m** (menú), **a** (automático), **q** (salir).

```bash
bash binsuid-scan.sh --quick --scan-only
bash binsuid-scan.sh --quick --auto -y
```

---

## Uso habitual

```bash
binsuid --scan-only
binsuid --auto --dry-run -y
binsuid --auto -y
binsuid --json --scan-only --quick
```

---

## Avisos normales

| Mensaje | Significado |
|---------|-------------|
| `getcap not found` | Falta `libcap2-bin` |
| `sudo not found` | Sin sudo; el resto del escaneo sigue |
| SUID de sistema ocultos | Filtrado de ruido habitual |

---

## Problemas frecuentes

| Error | Solución |
|-------|----------|
| `binsuid: command not found` | `source ~/.bashrc` |
| `externally-managed-environment` | Usa `pipx` o `get-binsuid.sh` |
| Sin Python en el objetivo | Usa `binsuid-scan.sh` |

---

English guide: [INSTALL.md](INSTALL.md)
