# setup.py
# Interactive setup script for Zenith Hybrid Threat Detection Engine.
import os
import sys
import subprocess
import shutil
from pathlib import Path

def print_banner():
    print("=" * 60)
    print("      ZENITH HYBRID THREAT DETECTION ENGINE - SETUP")
    print("=" * 60)
    print("This script will help you configure your environment.\n")

def check_python_version():
    if sys.version_info < (3, 8):
        print("[-] Error: Python 3.8 or higher is required.")
        sys.exit(1)
    print("[+] Python version check passed.")

def setup_virtualenv():
    venv_dir = Path("venv")
    if not venv_dir.exists():
        print("[*] Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print("[+] Virtual environment created.")
    else:
        print("[+] Virtual environment already exists.")
    return venv_dir

def install_dependencies():
    print("[*] Installing dependencies...")
    pip_path = "venv/bin/pip" if os.name != "nt" else "venv/Scripts/pip.exe"
    
    # Install backend dependencies
    subprocess.run([pip_path, "install", "-r", "backend/requirements.txt"], check=True)
    # Install desktop-app dependencies
    subprocess.run([pip_path, "install", "-r", "desktop-app/requirements.txt"], check=True)
    
    # Ensure 'python-dotenv' is installed for this script to work if needed
    subprocess.run([pip_path, "install", "python-dotenv"], check=True)
    
    print("[+] Dependencies installed successfully.")

def configure_env():
    env_example = Path("backend/.env.example")
    env_file = Path("backend/.env")
    
    if not env_file.exists():
        print("[*] Creating .env file from template...")
        shutil.copy(env_example, env_file)
    else:
        print("[+] .env file already exists.")

    # Read current .env content
    with open(env_file, "r") as f:
        lines = f.readlines()

    # Prompt for VirusTotal API Key
    print("\n" + "-" * 40)
    print("VIRUSTOTAL API CONFIGURATION")
    print("To use the cloud-based threat intelligence, you need a VirusTotal API key.")
    print("You can get a free key at: https://www.virustotal.com/gui/join-us")
    print("-" * 40)
    
    # Try to find current VT_API_KEY
    current_key = ""
    for line in lines:
        if line.startswith("VT_API_KEY="):
            current_key = line.split("=", 1)[1].strip()
            break
            
    prompt = f"Enter your VirusTotal API Key [{current_key}]: " if current_key else "Enter your VirusTotal API Key: "
    vt_key = input(prompt).strip()
    
    if not vt_key and current_key:
        vt_key = current_key

    # Update .env
    new_lines = []
    found_vt = False
    for line in lines:
        if line.startswith("VT_API_KEY="):
            new_lines.append(f"VT_API_KEY={vt_key}\n")
            found_vt = True
        else:
            new_lines.append(line)
    
    if not found_vt:
        new_lines.append(f"VT_API_KEY={vt_key}\n")

    with open(env_file, "w") as f:
        f.writelines(new_lines)
    
    print("[+] .env configuration updated.")

def create_start_scripts():
    print("[*] Creating start scripts...")
    if os.name == "nt": # Windows
        with open("start_zenith.bat", "w") as f:
            f.write("@echo off\n")
            f.write("start /B venv\\Scripts\\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000\n")
            f.write("timeout /t 5\n")
            f.write("venv\\Scripts\\python.exe desktop-app/app.py\n")
        print("[+] Created start_zenith.bat")
    else: # Linux/Mac
        with open("start_zenith.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("source venv/bin/activate\n")
            f.write("python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 &\n")
            f.write("sleep 5\n")
            f.write("python3 desktop-app/app.py\n")
            f.write("kill $!\n")
        os.chmod("start_zenith.sh", 0o755)
        print("[+] Created start_zenith.sh")

def main():
    print_banner()
    check_python_version()
    setup_virtualenv()
    install_dependencies()
    configure_env()
    create_start_scripts()
    print("\n[+] Setup complete! You can now start the application using:")
    if os.name == "nt":
        print("    .\\start_zenith.bat")
    else:
        print("    ./start_zenith.sh")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Setup cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An error occurred: {e}")
        sys.exit(1)
