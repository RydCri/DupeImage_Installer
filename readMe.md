A simple app built with tkinter and pyinstaller to organize your files.
<br>
1. Select a folder full of duplicate images you want sorted.
2. The app scans your folder and identifies duplicate images by comparing file hashes.
3. A prompt window will confirm you want to move your duplicates.
4. All duplicates are moved into a new 'duplicates' subfolder.

<br>
This repo is for contains the source code and can be used for learning the tools used, check the releases page if you'd like the standalone app.
<br>
Available for macOS and windows.

Build command:
<br>
MacOS
<br>
pyinstaller --onefile --windowed --icon=app_icon.icns --name "DuplicateImageFinder_v1.0.0" find_duplicate_images.py
<br>
Windows
<br>
pyinstaller --onefile --windowed --icon=dupy.ico --name "DuplicateImageFinder_v1.0.0" find_duplicate_images_windows.py
