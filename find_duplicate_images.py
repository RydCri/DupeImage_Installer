import os
import shutil
import hashlib
import uuid
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
import imagehash
import threading

# --- Configuration ---
APP_VERSION = "1.0.0" # Current version: Major.Minor.Patch
DUPLICATES_FOLDER_NAME = "duplicates"
IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']
PHASH_CUTOFF = 5 # Used for fuzzy matching. Lower number means stricter matching.

# --- Core Helper Functions ---

def get_image_paths(folder_path, recursive=True):
    """
    Generates a list of all files with recognized image extensions in the folder,
    with an option to search subfolders.
    """
    image_paths = []

    if recursive:
        # Recursive search using os.walk
        for root, _, files in os.walk(folder_path):
            # Exclude the duplicates folder itself from scanning
            if DUPLICATES_FOLDER_NAME in root.split(os.sep):
                continue

            for filename in files:
                if any(filename.lower().endswith(ext) for ext in IMAGE_EXTENSIONS):
                    image_paths.append(os.path.join(root, filename))
    else:
        # Non-recursive search (top level only)
        for filename in os.listdir(folder_path):
            if any(filename.lower().endswith(ext) for ext in IMAGE_EXTENSIONS):
                full_path = os.path.join(folder_path, filename)
                # We only care about files, not subdirectories in non-recursive mode
                if os.path.isfile(full_path):
                    image_paths.append(full_path)

    return image_paths

def calculate_file_hash(filepath, blocksize=65536):
    """Calculates the SHA256 hash of a file for exact duplicate detection."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as afile:
            buf = afile.read(blocksize)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(blocksize)
        return hasher.hexdigest()
    except Exception:
        return None

def calculate_perceptual_hash(filepath):
    """
    Calculates the perceptual hash (pHash) of an image for fuzzy duplicate detection.
    Returns the hash as a string.
    """
    try:
        img = Image.open(filepath)
        # We use dhash for better performance and results on common images
        p_hash = str(imagehash.dhash(img))
        return p_hash
    except Exception:
        # File might not be a readable image (e.g., corrupt or zero-byte file)
        return None

# --- GUI Application Class ---

class DuplicateFinderApp:
    def __init__(self, master):
        self.master = master
        master.title("Image Duplicate Finder")
        master.resizable(False, False)

        self.target_folder = tk.StringVar()
        self.target_folder.set("No folder selected.")

        self.recursive_scan = tk.BooleanVar(value=True)
        self.scan_mode = tk.StringVar(value="exact")
        self.is_scanning = False
        self.stop_event = threading.Event() # Event to signal the scan thread to stop

        # Style Configuration
        style = ttk.Style()
        style.theme_use('aqua')
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#A71BDE')
        style.configure('Success.TLabel', background='#a3d9a3', foreground='#A71BDE', padding=5, font=('Arial', 10, 'italic'))

        # 1. Folder Selection Frame
        self.folder_frame = ttk.Frame(master, padding="10")
        self.folder_frame.pack(fill='x')

        self.folder_label = ttk.Label(self.folder_frame, text="Target Path:", font=('Arial', 10, 'bold'))
        self.folder_label.pack(side='left', padx=(0, 5))

        self.folder_entry = ttk.Label(self.folder_frame, textvariable=self.target_folder,
                                      background='#A71BDE', relief='groove', anchor='w',
                                      style='TLabel')
        self.folder_entry.pack(side='left', fill='x', expand=True, padx=(0, 10), ipady=3)

        self.select_button = ttk.Button(self.folder_frame, text="1. Select Folder", command=self.select_folder)
        self.select_button.pack(side='right')

        # 2. Scan Mode Selection Frame
        self.mode_frame = ttk.Frame(master, padding="10 10 10 0")
        self.mode_frame.pack(fill='x')
        ttk.Label(self.mode_frame, text="Select Scan Mode:", font=('Arial', 10, 'bold')).pack(anchor='w', pady=(0, 5))

        ttk.Radiobutton(self.mode_frame, text="Exact Match (Fastest)",
                        variable=self.scan_mode, value='exact').pack(anchor='w', padx=10)
        ttk.Radiobutton(self.mode_frame, text="Fuzzy Match (Visual Similarity)",
                        variable=self.scan_mode, value='fuzzy').pack(anchor='w', padx=10)


        # 3. Control and Options Frame
        self.control_frame = ttk.Frame(master, padding="10")
        self.control_frame.pack(fill='x')

        # Frame for Start/Stop buttons
        self.action_frame = ttk.Frame(self.control_frame)
        self.action_frame.pack(fill='x', pady=(0, 5))

        self.scan_button = ttk.Button(self.action_frame, text="2. Start Scan", command=self.run_scan_thread, state=tk.DISABLED)
        self.scan_button.pack(side='left', expand=True, fill='x', padx=(0, 5))

        self.stop_button = ttk.Button(self.action_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side='left', expand=True, fill='x', padx=(5, 0))

        # Checkbox for recursion
        self.recursive_check = ttk.Checkbutton(self.control_frame,
                                               text="Include Subfolders (Recursive Search)",
                                               variable=self.recursive_scan)
        self.recursive_check.pack(anchor='w', pady=(0, 5))

        # 4. Status and Progress
        self.status_text = tk.StringVar()
        self.status_text.set("1. Click 'Select Folder' to choose the directory to scan.")

        self.status_label = ttk.Label(master, textvariable=self.status_text, padding="10", font=('Arial', 10, 'italic'), anchor='w')
        self.status_label.pack(fill='x')

        # Version Label
        self.version_label = ttk.Label(master, text=f"Version {APP_VERSION}", font=('Arial', 8), anchor='e', foreground='#888888')
        self.version_label.pack(fill='x', padx=10, pady=(0, 5))

        # CRITICAL FIX: Force the window to draw and size correctly immediately
        master.minsize(600,100)
        master.update()
        master.geometry(f"{master.winfo_reqwidth()}x{master.winfo_reqheight()}")

    def update_status(self, message):
        """Helper to update the status label in the GUI."""
        self.status_text.set(message)
        self.master.update_idletasks()

    def select_folder(self):
        """Opens a dialog to select the folder and updates the path."""
        initial_directory = os.path.expanduser("~")
        folder_selected = filedialog.askdirectory(title="Select Folder to Scan", initialdir=initial_directory)

        if folder_selected:
            self.target_folder.set(folder_selected)
            self.folder_entry.config(style='Success.TLabel')
            self.scan_button.config(state=tk.NORMAL)
            self.update_status(f"Folder selected. Ready to scan {os.path.basename(folder_selected)}. Press 'Start Scan'.")
        else:
            self.folder_entry.config(style='TLabel', background='#e0e0e0')
            self.target_folder.set("No folder selected.")
            self.scan_button.config(state=tk.DISABLED)
            self.update_status("Folder selection cancelled. Please try again.")

    def run_scan_thread(self):
        """Sets up and starts the scan in a separate thread."""
        if self.is_scanning:
            return

        self.stop_event.clear()
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.select_button.config(state=tk.DISABLED)

        # Start the actual scanning function in a new thread
        threading.Thread(target=self.start_scan_logic, daemon=True).start()

    def stop_scan(self):
        """Signals the running thread to stop."""
        if self.is_scanning:
            self.update_status("Scan stop requested. Finishing current file...")
            self.stop_event.set() # Set the flag to stop the thread

    def start_scan_logic(self):
        """Contains the main thread logic for finding and moving files."""
        folder_path = self.target_folder.get()
        mode = self.scan_mode.get()
        total_moved = 0

        try:
            self.update_status(f"Starting scan in {mode.upper()} mode...")

            # --- 1. HASHING AND GROUPING ---

            is_recursive = self.recursive_scan.get()
            image_paths = get_image_paths(folder_path, recursive=is_recursive)

            if not image_paths:
                self.update_status("No images found to process.")
                return 0

            self.update_status(f"Found {len(image_paths)} files. Calculating hashes...")

            hash_map = {}
            total_files = len(image_paths)

            if mode == 'exact':
                # Exact Match (SHA256)
                for i, image_path in enumerate(image_paths):
                    if self.stop_event.is_set(): break
                    if (i + 1) % 5 == 0 or i == total_files - 1:
                        self.update_status(f"Progress: {i+1}/{total_files} | Hashing: {os.path.basename(image_path)}")

                    file_hash = calculate_file_hash(image_path)

                    if file_hash:
                        if file_hash not in hash_map:
                            hash_map[file_hash] = []
                        hash_map[file_hash].append(image_path)

            elif mode == 'fuzzy':
                hash_groups = []

                for i, image_path in enumerate(image_paths):
                    if self.stop_event.is_set(): break
                    if (i + 1) % 5 == 0 or i == total_files - 1:
                        self.update_status(f"Progress: {i+1}/{total_files} | Phashing: {os.path.basename(image_path)}")

                    p_hash = calculate_perceptual_hash(image_path)
                    if not p_hash: continue

                    is_duplicate = False

                    for group in hash_groups:
                        original_p_hash = group[0]
                        hash_difference = imagehash.hex_to_hash(original_p_hash) - imagehash.hex_to_hash(p_hash)

                        if hash_difference <= PHASH_CUTOFF:
                            group[1].append(image_path)
                            is_duplicate = True
                            break

                    if not is_duplicate:
                        hash_groups.append([p_hash, [image_path]])

                for group in hash_groups:
                    group_key = str(uuid.uuid4())
                    hash_map[group_key] = group[1]


            # --- 2. COUNTING DUPLICATES ---

            duplicates_to_move = []
            for file_hash, file_list in hash_map.items():
                if len(file_list) > 1:
                    # Append all files except the first (the original to keep)
                    duplicates_to_move.extend(file_list[1:])

            num_duplicates = len(duplicates_to_move)

            if num_duplicates == 0:
                messagebox.showinfo("Scan Complete", "No duplicates found!")
                self.update_status("Scan complete. No duplicates found. Ready for a new scan.")
                return 0

            # --- 3. CONFIRMATION AND MOVING ---

            self.update_status(f"Found {num_duplicates} duplicate(s). Awaiting confirmation to move.")

            # Show confirmation dialog
            confirm = messagebox.askyesno(
                "Confirm Duplicate Move",
                f"The scan found {num_duplicates} duplicate image file(s).\n\n"
                f"Do you want to move these files to a subfolder named '{DUPLICATES_FOLDER_NAME}' inside the selected directory?\n\n"
                f"The first file found in each duplicate group will be kept as the original."
            )

            if not confirm:
                self.update_status("Move operation cancelled by user. Ready for a new scan.")
                return 0

            # Proceed with moving files
            duplicate_dir = os.path.join(folder_path, DUPLICATES_FOLDER_NAME)
            if not os.path.exists(duplicate_dir):
                os.makedirs(duplicate_dir)

            self.update_status(f"Moving {num_duplicates} duplicate(s) now...")

            for duplicate_path in duplicates_to_move:
                if self.stop_event.is_set(): break # Check stop event during move

                try:
                    filename = os.path.basename(duplicate_path)
                    destination_path = os.path.join(duplicate_dir, filename)

                    if os.path.exists(destination_path):
                        base, ext = os.path.splitext(filename)
                        new_filename = f"{base}_{uuid.uuid4().hex[:6]}{ext}"
                        destination_path = os.path.join(duplicate_dir, new_filename)

                    shutil.move(duplicate_path, destination_path)
                    total_moved += 1

                    self.update_status(f"Moved {total_moved}/{num_duplicates} duplicates. Last file: {os.path.basename(destination_path)}")

                except Exception as e:
                    print(f"Error moving file {duplicate_path}: {e}")
                    continue

                    # --- 4. FINAL RESULT REPORTING ---

            if self.stop_event.is_set():
                messagebox.showwarning("Scan Halted", f"Scan was stopped by the user.\n{total_moved} duplicates were moved before halting.")
                self.update_status(f"Scan halted. {total_moved} duplicates were moved.")
            else:
                messagebox.showinfo("Scan Complete", f"Scan finished successfully!\nTotal duplicates moved: {total_moved}")
                self.update_status(f"Scan complete. {total_moved} duplicates moved. Ready for a new folder scan.")


        except Exception as e:
            # Handle unexpected errors
            messagebox.showerror("An Error Occurred", f"An unexpected error occurred during the scan: {e}")
            self.update_status("Scan failed due to an error.")
            print(f"FATAL ERROR: {e}")

        finally:
            # Always reset state whether successful, halted, or failed
            self.is_scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.select_button.config(state=tk.NORMAL)

# --- Execution ---
if __name__ == "__main__":
    # Ensure you have the required libraries installed:
    # pip3 install Pillow imagehash

    root = tk.Tk()
    app = DuplicateFinderApp(root)
    root.mainloop()