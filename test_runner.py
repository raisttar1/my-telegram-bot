import sys, subprocess, pathlib
DAEMONS = {"bot.py", "main.py"}
def main():
    py_files = [f for f in pathlib.Path.cwd().glob("*.py") if not any(p in {".venv", "venv", "__pycache__"} for p in f.parts) and f.name != pathlib.Path(__file__).name]
    failed = False
    print("🧪 Build & Syntax Check")
    for f in py_files:
        if f.name in DAEMONS:
            res = subprocess.run([sys.executable, "-m", "py_compile", str(f)], capture_output=True)
            ok = res.returncode == 0
            print(f"🔍 Daemon {f.name}: {'✅ PASSED' if ok else '❌ FAILED'}")
        else:
            res = subprocess.run([sys.executable, str(f)], capture_output=True)
            ok = res.returncode == 0
            print(f"▶️ Script {f.name}: {'✅ PASSED' if ok else '❌ FAILED'}")
        if not ok: failed = True
    sys.exit(1 if failed else 0)
if __name__ == "__main__": main()
