"""Build standalone zabbix-autodiscovery.exe with PyInstaller."""
import subprocess
import sys
from pathlib import Path


def build():
    root = Path(__file__).resolve().parent
    data_src = root / "src" / "zabbix_autodiscovery" / "data"
    entry = root / "src" / "zabbix_autodiscovery" / "__main__.py"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name=zabbix-autodiscovery",
        "--clean",
        "--noconfirm",
        "--onefile",
        f"--add-data={data_src};zabbix_autodiscovery/data",
        "--paths",
        str(root / "src"),
        str(entry),
    ]

    print("Executando PyInstaller para compilar zabbix-autodiscovery.exe...")
    print("Comando:", " ".join(cmd))
    res = subprocess.run(cmd, check=False)
    if res.returncode == 0:
        exe_path = root / "dist" / "zabbix-autodiscovery.exe"
        print(f"\n[SUCESSO] Executável compilado com sucesso em: {exe_path}")
        print("Você pode mover o executável para qualquer pasta ou computador com Windows.")
    else:
        print(f"\n[ERRO] Falha ao compilar executável (código {res.returncode})")
        sys.exit(res.returncode)


if __name__ == "__main__":
    build()

