import subprocess
import sys

def install_packages():
    required_packages = ["requests", "colorama"]

    for package in required_packages:
        try:
            __import__(package)
            print(f"{package} kütüphanesi zaten yüklü.")
        except ImportError:
            print(f"{package} kütüphanesi yüklü değil, yükleniyor...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

if __name__ == "__main__":
    install_packages()
