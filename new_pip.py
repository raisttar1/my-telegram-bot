import subprocess
import sys


def install(package):
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", package]
    )


def main():
    print("#" * 67)
    print("#                              STARTED                            #")
    print("#" * 67)

    packages = [
        "pyTelegramBotAPI",
        "python-cfonts",
        "fake-useragent",
        "pyfiglet",
        "requests",
        "beautifulsoup4",
        "colorama",
        "user-agent",
        "PySocks",
        "curl2pyreqs",
    ]

    failed = []
    for package in packages:
        try:
            install(package)
            print(f"[OK] installed {package}")
        except subprocess.CalledProcessError as exc:
            failed.append(package)
            print(f"[WARN] failed to install {package} (exit {exc.returncode})", file=sys.stderr)

    print("#" * 67)
    print("#                   Done Installation Of Pips                     #")
    print("#" * 67)

    if failed:
        print(f"[FAIL] {len(failed)} package(s) could not be installed: {', '.join(failed)}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
