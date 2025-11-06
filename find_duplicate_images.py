import os
import shutil
import hashlib
import uuid
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
import imagehash

# --- Configuration ---
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

        # New variables for controls
        self.recursive_scan = tk.BooleanVar(value=True)
        self.scan_mode = tk.StringVar(value="exact") # 'exact' or 'fuzzy'

        # Style Configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0')
        style.configure('Success.TLabel', background='#a3d9a3', foreground='#000000', padding=5, font=('Arial', 10, 'italic'))

        # 1. Folder Selection Frame
        self.folder_frame = ttk.Frame(master, padding="10")
        self.folder_frame.pack(fill='x')

        self.folder_label = ttk.Label(self.folder_frame, text="Target Path:", font=('Arial', 10, 'bold'))
        self.folder_label.pack(side='left', padx=(0, 5))

        self.folder_entry = ttk.Label(self.folder_frame, textvariable=self.target_folder,
                                      background='#e0e0e0', relief='groove', anchor='w',
                                      style='TLabel')
        self.folder_entry.pack(side='left', fill='x', expand=True, padx=(0, 10), ipady=3)

        self.select_button = ttk.Button(self.folder_frame, text="Select Folder", command=self.select_folder)
        self.select_button.pack(side='right')

        # 2. Scan Mode Selection Frame (New)
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

        self.scan_button = ttk.Button(self.control_frame, text="2. Start Scan and Move Duplicates", command=self.start_scan, state=tk.DISABLED)
        self.scan_button.pack(fill='x', pady=(0, 5))

        self.recursive_check = ttk.Checkbutton(self.control_frame,
                                               text="Include Subfolders (Recursive Search)",
                                               variable=self.recursive_scan)
        self.recursive_check.pack(anchor='w', pady=(0, 5))

        # 4. Status and Progress
        self.status_text = tk.StringVar()
        self.status_text.set("1. Click 'Select Folder' to choose the directory to scan.")

        self.status_label = ttk.Label(master, textvariable=self.status_text, padding="10", font=('Arial', 10, 'italic'), anchor='w')
        self.status_label.pack(fill='x')

        # CRITICAL FIX: Force the window to draw and size correctly immediately
        master.update()
        master.minsize(600, 100)
        master.geometry(f"{master.winfo_reqwidth()}x{master.winfo_reqheight()}")

    def select_folder(self):
        """Opens a dialog to select the folder and updates the path."""
        initial_directory = os.path.expanduser("~")
        folder_selected = filedialog.askdirectory(title="Select Folder to Scan", initialdir=initial_directory)

        if folder_selected:
            self.target_folder.set(folder_selected)
            self.folder_entry.config(style='Success.TLabel')
            self.scan_button.config(state=tk.NORMAL)
            self.update_status(f"Folder selected. Ready to scan {os.path.basename(folder_selected)}. Press 'Start Scan' to continue.")
        else:
            self.folder_entry.config(style='TLabel', background='#e0e0e0')
            self.target_folder.set("No folder selected.")
            self.scan_button.config(state=tk.DISABLED)
            self.update_status("Folder selection cancelled. Please try again.")

    def update_status(self, message):
        """Helper to update the status label in the GUI."""
        self.status_text.set(message)
        self.master.update_idletasks()

    def start_scan(self):
        """Initiates the duplicate finding and moving process."""
        folder_path = self.target_folder.get()

        if not os.path.isdir(folder_path):
            messagebox.showerror("Error", "Please select a valid folder before starting the scan.")
            return

        self.scan_button.config(state=tk.DISABLED)
        self.select_button.config(state=tk.DISABLED)

        mode = self.scan_mode.get()
        if mode == 'exact':
            mode_text = "Exact Match (SHA256)"
        else:
            mode_text = "Fuzzy Match (pHash)"

        self.update_status(f"Starting scan in {mode_text} mode... This may take a moment.")

        try:
            total_moved = self.find_and_move_duplicates(folder_path, mode)

            messagebox.showinfo("Scan Complete", f"Scan finished successfully!\nTotal duplicates moved: {total_moved}\n(All duplicates are now in the '{DUPLICATES_FOLDER_NAME}' subfolder within the scanned folder.)")
            self.update_status(f"Scan complete. {total_moved} duplicates moved. Ready for a new folder scan.")
        except Exception as e:
            messagebox.showerror("An Error Occurred", f"An unexpected error occurred during the scan: {e}")
            self.update_status("Scan failed due to an error. Check console for details.")
            print(f"FATAL ERROR: {e}")

        self.scan_button.config(state=tk.NORMAL)
        self.select_button.config(state=tk.NORMAL)


    def find_and_move_duplicates(self, folder_path, mode):
        """
        Finds duplicates by comparing hashes and moves them.
        """
        duplicate_dir = os.path.join(folder_path, DUPLICATES_FOLDER_NAME)
        if not os.path.exists(duplicate_dir):
            os.makedirs(duplicate_dir)

        is_recursive = self.recursive_scan.get()
        image_paths = get_image_paths(folder_path, recursive=is_recursive)

        if not image_paths:
            self.update_status("No images found to process.")
            return 0

        self.update_status(f"Found {len(image_paths)} files. Calculating hashes...")

        # 1. Hashing and Grouping
        # hash_map stores: {hash_value: [list of file paths]}
        hash_map = {}
        duplicate_count = 0
        total_files = len(image_paths)

        if mode == 'exact':
            # Exact Match (SHA256)
            for i, image_path in enumerate(image_paths):
                if (i + 1) % 5 == 0 or i == total_files - 1:
                    self.update_status(f"Progress: {i+1}/{total_files} | Hashing: {os.path.basename(image_path)}")

                file_hash = calculate_file_hash(image_path)

                if file_hash:
                    if file_hash not in hash_map:
                        hash_map[file_hash] = []
                    hash_map[file_hash].append(image_path)

        elif mode == 'fuzzy':
            # Fuzzy Match (pHash) - uses a list of lists to group similar hashes
            # Instead of a strict map, we use a list of hash groups
            hash_groups = [] # Format: [[phash_of_original, path_of_original, phash_list_of_duplicates], ...]

            for i, image_path in enumerate(image_paths):
                if (i + 1) % 5 == 0 or i == total_files - 1:
                    self.update_status(f"Progress: {i+1}/{total_files} | Phashing: {os.path.basename(image_path)}")

                p_hash = calculate_perceptual_hash(image_path)
                if not p_hash:
                    continue

                is_duplicate = False

                for group in hash_groups:
                    # Check if the new image's hash is close to the original image's hash in the group
                    original_p_hash = group[0]
                    # The imagehash library allows subtraction to find the difference (Hamming distance)
                    hash_difference = imagehash.hex_to_hash(original_p_hash) - imagehash.hex_to_hash(p_hash)

                    if hash_difference <= PHASH_CUTOFF:
                        # Found a match! The new image is a duplicate of the original in this group
                        group[1].append(image_path) # Add path to the list of duplicates
                        is_duplicate = True
                        break

                if not is_duplicate:
                    # This is a new, unique image, so start a new group
                    hash_groups.append([p_hash, [image_path]]) # Format: [original_hash, [path_1, path_2, ...]]

            # Convert the fuzzy groups format into the exact match map format for reuse
            # For fuzzy matching, the 'hash' is arbitrary, but we use it to represent the group
            for group in hash_groups:
                # Use a UUID as the group key since the pHash is only used for comparison, not as a strict key
                group_key = str(uuid.uuid4())
                hash_map[group_key] = group[1] # The list of paths


        # 2. Moving Duplicates (Shared logic for both Exact and Fuzzy)
        self.update_status("Moving duplicates...")
        for file_hash, file_list in hash_map.items():
            if len(file_list) > 1:
                # The first file is kept as the original; subsequent files are duplicates to be moved
                for duplicate_path in file_list[1:]:
                    try:
                        filename = os.path.basename(duplicate_path)
                        destination_path = os.path.join(duplicate_dir, filename)

                        # Handle file name collisions in the duplicates folder
                        if os.path.exists(destination_path):
                            base, ext = os.path.splitext(filename)
                            # Use a short unique ID to rename the file to prevent overwrite
                            new_filename = f"{base}_{uuid.uuid4().hex[:6]}{ext}"
                            destination_path = os.path.join(duplicate_dir, new_filename)

                        shutil.move(duplicate_path, destination_path)
                        duplicate_count += 1

                        self.update_status(f"Moved {duplicate_count} duplicates. Last file: {os.path.basename(destination_path)}")

                    except Exception as e:
                        print(f"Error moving file {duplicate_path}: {e}")
                        continue

        return duplicate_count

# --- Execution ---
if __name__ == "__main__":
    # --- IMPORTANT DEPENDENCIES ---
    # You need these libraries installed on your Mac:
    # 1. Pillow:       pip3 install Pillow
    # 2. imagehash:    pip3 install imagehash
    # ------------------------------

    root = tk.Tk()
    app = DuplicateFinderApp(root)
    root.mainloop()