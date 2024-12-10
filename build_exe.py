import PyInstaller.__main__
import os
import sys
import time
import shutil

def clean_dist():
    """Clean up the dist directory"""
    dist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dist')
    if os.path.exists(dist_path):
        try:
            shutil.rmtree(dist_path)
        except PermissionError:
            print("Cannot remove dist folder. Please close any running instances of the application.")
            print("Waiting 5 seconds before retrying...")
            time.sleep(5)
            try:
                shutil.rmtree(dist_path)
            except PermissionError:
                print("Still cannot remove dist folder. Please close the application manually and try again.")
                sys.exit(1)

def build_exe():
    # Get the directory containing your script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Clean up first
    clean_dist()

    # Define additional data files
    additional_files = [
        ('malware_scanner.py', '.'),
        ('malware_rules.yar', '.'),
    ]

    # Build command
    cmd = [
        'scanner_gui.py',  # Your main script
        '--onefile',  # Create a single executable
        '--windowed',  # Don't show console window
        '--icon=scanner.ico',  # Add an icon
        '--name=MalwareScanner',  # Name of the executable
        '--clean',  # Clean PyInstaller cache
    ]

    # Add data files
    for src, dst in additional_files:
        src_path = os.path.join(script_dir, src)
        if os.path.exists(src_path):
            cmd.extend(['--add-data', f'{src_path};{dst}'])

    # Run PyInstaller
    try:
        PyInstaller.__main__.run(cmd)
        print("Build completed successfully!")
    except Exception as e:
        print(f"Build failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    build_exe() 