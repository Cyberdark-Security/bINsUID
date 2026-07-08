# Guía de instalación por entorno

> **Un solo comando para casi cualquier lab** (recomendado):

```bash
curl -fsSL https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/get-binsuid.sh | bash
source ~/.bashrc
binsuid --scan-only
```

Solo necesitas **Linux + bash + curl** (o wget) en el host de instalación. **Python 3 es opcional**: sin él, `binsuid` ejecuta el escáner bash (`binsuid-scan`).

---

## Qué necesita el sistema

| Herramienta | ¿Obligatoria? | Si no está |
|-------------|---------------|------------|
| Linux + bash | **Sí** | No se puede ejecutar |
| curl o wget | **Sí** (para descargar) | `docker cp` del script o copia manual |
| Python 3.9+ | No | Modo bash: recon sin auto-escalada |
| git | No | No uses `git clone` en labs mínimos |
| pip / pipx | No | El script no los usa |
| sudo | No | El script no lo usa |
| getcap | No | Aviso: no escanea capabilities |
| sudo sin password | No | Aviso: no escanea reglas sudo útiles |

---

## Por tipo de laboratorio

### Docker / CTF (usuario `hacker`, sin sudo)

```bash
curl -fsSL https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/get-binsuid.sh | bash
source ~/.bashrc
binsuid --scan-only
```

### Sin instalar nada (una sola vez, sin alias)

```bash
curl -sL https://github.com/Cyberdark-Security/bINsUID/archive/refs/heads/main.tar.gz | tar xz -C /tmp
cd /tmp/bINsUID-main
/usr/bin/python3 -m binsuid --scan-only
```

### Kali Linux (tu máquina o VM con pipx)

```bash
sudo apt install -y pipx
pipx ensurepath
# nueva terminal
pipx install https://github.com/Cyberdark-Security/bINsUID.git
binsuid --scan-only
```

O desde clone:

```bash
git clone https://github.com/Cyberdark-Security/bINsUID.git
cd bINsUID
./scripts/install-kali.sh
```

### VM con root y paquetes Debian

```bash
sudo dpkg -i binsuid_*.deb    # desde GitHub Releases
# o
pip install --break-system-packages .
```

---

## Uso después de instalar

```bash
binsuid --scan-only       # ver objetivos (recomendado la primera vez)
binsuid --auto --dry-run -y   # ver qué haría sin ejecutar
binsuid --auto -y         # escalar al mejor objetivo
binsuid --json            # salida JSON
```

---

## Mensajes que NO son errores

| Mensaje | Significado |
|---------|-------------|
| `getcap not found` | El lab no tiene `libcap2-bin`. El escaneo SUID sigue funcionando. |
| `sudo: a password is required` | Tu usuario no tiene sudo libre. El escaneo SUID sigue funcionando. |
| `18 system SUID binaries hidden` | Normal. bINsUID oculta ruido y muestra el objetivo del lab arriba. |

---

## Errores reales y solución

| Error | Causa | Solución |
|-------|-------|----------|
| `git: command not found` | Lab mínimo sin git | Usa `get-binsuid.sh`, no `git clone` |
| `pip: command not found` | Sin pip | Usa `get-binsuid.sh` |
| `externally-managed-environment` | Kali bloquea pip global | Usa `pipx` o `get-binsuid.sh` |
| `hacker is not in the sudoers` | Sin sudo | Usa `get-binsuid.sh` (no necesita sudo) |
| `binsuid: command not found` | PATH no actualizado | `source ~/.bashrc` o `export PATH="$HOME/bin:$PATH"` |
| `No module named pip` | venv roto en PATH | `rm -rf ~/.local/venvs/binsuid` y usa `get-binsuid.sh` |

---

## Para instructores

Pon esto en la descripción del lab o en el README del curso:

```bash
curl -fsSL https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/get-binsuid.sh | bash && source ~/.bashrc && binsuid --scan-only
```

[English install guide](../README.md#install)
