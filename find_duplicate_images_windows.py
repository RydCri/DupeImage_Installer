import os
import shutil
import threading
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from PIL import Image, ImageChops
    import imagehash
except ImportError:
    # A simple message for users if they run the script without libraries
    tk.messagebox.showerror(
        "Error",
        "Required libraries (Pillow, imagehash) not found. "
        "Please install them using: pip install Pillow imagehash"
    )
    exit()

# --- Configuration ---
APP_VERSION = "1.0.0" # Current version: Major.Minor.Patch
DUPLICATES_FOLDER_NAME = "duplicates"
IMAGE_EXTENSIONS = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp')
# For Fuzzy Match (pHash): determines how similar hashes need to be.
# 0 is identical, higher numbers mean more fuzziness. 8 is a common starting point.
PHASH_CUTOFF = 8


def get_image_paths(folder_path, recursive=True):
    """Recursively or non-recursively finds all image files in a directory."""
    image_paths = []

    if recursive:
        # Recursive scan using os.walk (searches subfolders)
        for dirpath, _, filenames in os.walk(folder_path):
            for f in filenames:
                if f.lower().endswith(IMAGE_EXTENSIONS):
                    image_paths.append(os.path.join(dirpath, f))
    else:
        # Non-recursive scan using os.listdir (searches top level only)
        for f in os.listdir(folder_path):
            full_path = os.path.join(folder_path, f)
            if os.path.isfile(full_path) and f.lower().endswith(IMAGE_EXTENSIONS):
                image_paths.append(full_path)

    return image_paths


def calculate_sha256_hash(filepath):
    """Calculates the SHA256 hash for exact file matching."""
    try:
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as file:
            # Read in chunks to handle large files efficiently
            while chunk := file.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None # Return None if file is inaccessible


def calculate_perceptual_hash(filepath):
    """Calculates the perceptual hash (pHash) for fuzzy image matching."""
    try:
        img = Image.open(filepath)
        # Resize/convert image if necessary before hashing
        img = img.convert('RGB').resize((64, 64), Image.Resampling.LANCZOS)
        # Use 'ahash' for a reasonable balance of speed and accuracy
        return str(imagehash.average_hash(img))
    except Exception:
        return None


class DuplicateFinderApp:
    def __init__(self, master):
        self.master = master
        master.title("Image Duplicate Finder")
        self.master.tk_setPalette(background='#2e2e2e', foreground='white') # Apply dark theme palette
        self.folder_path = None
        self.scanning_thread = None
        self.stop_event = threading.Event()

        # --- Variables ---
        self.selected_path = tk.StringVar(value="Click 'Select Folder' to begin.")
        self.status_message = tk.StringVar(value="Waiting for folder selection...")
        self.scan_mode = tk.StringVar(value="sha256") # Default to Exact Match
        self.recursive_scan = tk.BooleanVar(value=True) # Default is checked (True)

        # --- Styling (Clam Dark Theme) ---
        style = ttk.Style(master)
        style.theme_use('clam')

        # Configure overall dark theme colors
        style.configure('.', background='#2e2e2e', foreground='white', font=('Inter', 10))
        style.configure('TFrame', background='#2e2e2e')
        style.configure('TLabel', background='#2e2e2e', foreground='white')
        style.configure('TCheckbutton', background='#2e2e2e', foreground='white')
        style.configure('TRadiobutton', background='#2e2e2e', foreground='white')

        # Path Display (Custom style for the path box)
        style.configure('Path.TLabel',
                        background='#3c3c3c',
                        foreground='white',
                        relief='flat',
                        anchor='w',
                        padding=5)

        # Button styling for better contrast
        style.map('TButton',
                  background=[('active', '#229933')],
                  foreground=[('active', '#555555')])

        # --- Layout ---
        main_frame = ttk.Frame(master, padding="15")
        main_frame.pack(fill='both', expand=True)

        # Path Display
        self.path_label = ttk.Label(main_frame, textvariable=self.selected_path,
                                    style='Path.TLabel',
                                    wraplength=420)
        self.path_label.pack(fill='x', pady=(0, 10))

        # Control Frame (Buttons and Recursive Checkbox)
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill='x', pady=(0, 10))

        # Select Folder Button
        ttk.Button(control_frame, text="1. Select Folder", command=self.select_folder).pack(side='left', padx=(0, 10))

        # Start/Stop Scan Buttons Frame
        self.action_frame = ttk.Frame(control_frame)
        self.action_frame.pack(side='left')

        self.scan_button = ttk.Button(self.action_frame, text="2. Start Scan and Move Duplicates", command=self.start_scan_thread, state='disabled')
        self.scan_button.pack(side='left')

        self.stop_button = ttk.Button(self.action_frame, text="Stop Scan", command=self.stop_scan, state='disabled')
        self.stop_button.pack(side='left', padx=(10, 0))

        # Recursive Checkbox
        self.recursive_check = ttk.Checkbutton(control_frame,
                                               text="Include Subfolders",
                                               variable=self.recursive_scan)
        self.recursive_check.pack(side='right')

        # --- Scan Mode Selection ---
        mode_frame = ttk.Frame(main_frame, padding="0 5")
        mode_frame.pack(fill='x', pady=(0, 10))

        ttk.Label(mode_frame, text="Select Scan Mode:", font=('Inter', 10, 'bold')).pack(side='left', padx=(0, 10))

        ttk.Radiobutton(mode_frame, text="Exact Match (Fastest)",
                        variable=self.scan_mode, value="sha256").pack(side='left', padx=(0, 10))

        ttk.Radiobutton(mode_frame, text="Fuzzy Match (Visual Similarity)",
                        variable=self.scan_mode, value="phash").pack(side='left')

        # Status Bar
        self.status_bar = ttk.Label(main_frame, textvariable=self.status_message,
                                    anchor='w',
                                    font=('Inter', 9))
        self.status_bar.pack(fill='x', pady=(10, 0))

        # Version Info
        ttk.Label(main_frame, text=f"Version: {APP_VERSION}",
                  anchor='e',
                  font=('Inter', 8)).pack(fill='x')


        # Force initial draw and set size
        master.update()
        master.minsize(600, master.winfo_height())
        master.maxsize(600, master.winfo_height())


    def select_folder(self):
        """Opens a dialog to select the folder for scanning."""
        selected = filedialog.askdirectory(
            title="Select Folder to Scan for Duplicates",
            initialdir=os.path.expanduser('~')
        )
        if selected:
            self.folder_path = selected
            # Visual confirmation: path turns light green
            self.path_label.configure(style='Selected.Path.TLabel')
            self.selected_path.set(f"Folder Selected: {self.folder_path}")
            self.status_message.set("2. Click 'Start Scan' when ready.")
            self.scan_button.config(state='normal')

            # Configure success color for selected path
            style = ttk.Style(self.master)
            style.configure('Selected.Path.TLabel',
                            background='#1a473b', # Dark green for success
                            foreground='white',
                            relief='flat',
                            anchor='w',
                            padding=5)
        else:
            self.selected_path.set("1. Click 'Select Folder' to begin.")
            self.scan_button.config(state='disabled')
            self.path_label.configure(style='Path.TLabel') # Reset style


    def start_scan_thread(self):
        """Starts the main scanning logic in a separate thread."""
        if not self.folder_path:
            messagebox.showwarning("Warning", "Please select a folder first.")
            return

        # Disable main controls and enable stop button
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.recursive_check.config(state='disabled')
        self.stop_event.clear() # Reset the stop flag
        self.status_message.set("Scanning started...")

        # Start the background thread
        self.scanning_thread = threading.Thread(target=self.find_and_move_duplicates)
        self.scanning_thread.start()


    def stop_scan(self):
        """Sets the stop flag to halt the scan thread gracefully."""
        self.stop_event.set()
        self.status_message.set("Scan stop requested. Waiting for thread to finish...")


    def find_and_move_duplicates(self):
        """
        Main logic: hashes files, finds duplicates, asks for confirmation, and moves them.
        Runs in a separate thread.
        """
        folder_path = self.folder_path
        scan_mode = self.scan_mode.get()
        is_recursive = self.recursive_scan.get()

        # Determine which hashing function to use
        if scan_mode == 'sha256':
            hash_func = calculate_sha256_hash
            mode_desc = "Exact Match (SHA256)"
        else: # phash
            hash_func = calculate_perceptual_hash
            mode_desc = f"Fuzzy Match (pHash - Cutoff {PHASH_CUTOFF})"

        self.status_message.set(f"Mode: {mode_desc}. Collecting image paths...")

        # Step 1: Get all image paths
        image_paths = get_image_paths(folder_path, recursive=is_recursive)

        if not image_paths:
            self.status_message.set("No images found in the selected directory.")
            self.reset_controls()
            return

        self.status_message.set(f"Found {len(image_paths)} images. Hashing files...")

        # Step 2: Hash files and group duplicates
        hashes = {} # Key: hash, Value: list of file paths with that hash

        for i, path in enumerate(image_paths):
            if self.stop_event.is_set(): break

            self.status_message.set(f"Hashing: {i + 1}/{len(image_paths)} - {os.path.basename(path)}")

            file_hash = hash_func(path)
            if file_hash is None: continue

            # For fuzzy match, check against existing hashes with cutoff
            if scan_mode == 'phash':
                is_duplicate = False
                for existing_hash in hashes:
                    # imagehash allows subtraction to get hamming distance (difference)
                    if existing_hash and (imagehash.hex_to_hash(existing_hash) - imagehash.hex_to_hash(file_hash) <= PHASH_CUTOFF):
                        hashes[existing_hash].append(path)
                        is_duplicate = True
                        break
                if not is_duplicate:
                    hashes[file_hash] = [path]

            # For exact match, just use direct dictionary lookup
            else: # sha256
                if file_hash not in hashes:
                    hashes[file_hash] = [path]
                else:
                    hashes[file_hash].append(path)


        # Step 3: Identify duplicate files to move
        files_to_move = []
        for file_list in hashes.values():
            # If a hash list has more than one file, all files EXCEPT the first one are duplicates
            if len(file_list) > 1:
                files_to_move.extend(file_list[1:])

        duplicate_count = len(files_to_move)

        if self.stop_event.is_set():
            self.status_message.set(f"Scan stopped by user. Found {duplicate_count} duplicates (not moved).")
            self.reset_controls()
            return

        if duplicate_count == 0:
            self.status_message.set("Scan complete. No duplicates found.")
            self.reset_controls()
            return

        # Step 4: Confirmation Prompt (Runs on the main thread via self.master.after)
        self.master.after(0, self.show_confirmation, folder_path, duplicate_count, files_to_move)


    def show_confirmation(self, folder_path, duplicate_count, files_to_move):
        """Shows the confirmation dialog and handles the move operation if confirmed."""

        # This function runs on the main thread after the scan thread finishes.

        if messagebox.askyesno(
                "Confirm File Move",
                f"Scan found {duplicate_count} duplicate files.\n\n"
                f"Move these {duplicate_count} files to a new '{DUPLICATES_FOLDER_NAME}' subfolder in:\n"
                f"{folder_path}?\n\n"
                f"(The first image found in each group will be kept as the original.)"
        ):
            self.status_message.set("Moving files...")
            self.master.update()

            # Move operation logic (runs on the main thread now for simplicity)
            self.move_duplicates(folder_path, files_to_move)

        else:
            self.status_message.set("Move canceled by user. Scan complete.")
            self.reset_controls()


    def move_duplicates(self, base_folder, files_to_move):
        """Moves the identified files into the duplicates folder."""

        duplicates_dir = os.path.join(base_folder, DUPLICATES_FOLDER_NAME)

        try:
            os.makedirs(duplicates_dir, exist_ok=True)

            moved_count = 0
            for filepath in files_to_move:
                if self.stop_event.is_set(): break

                # Check if file still exists (it shouldn't have been moved yet)
                if os.path.exists(filepath):
                    # Construct new path: /duplicates/original_filename.ext
                    new_filepath = os.path.join(duplicates_dir, os.path.basename(filepath))
                    shutil.move(filepath, new_filepath)
                    moved_count += 1

            if self.stop_event.is_set():
                final_msg = f"Move stopped by user. {moved_count} files moved successfully."
            else:
                final_msg = f"SUCCESS! Moved {moved_count} duplicate files to: {duplicates_dir}"

            self.status_message.set(final_msg)
            messagebox.showinfo("Complete", final_msg)

        except Exception as e:
            error_msg = f"An error occurred during move: {e}"
            self.status_message.set(error_msg)
            messagebox.showerror("Error", error_msg)

        self.reset_controls()


    def reset_controls(self):
        """Resets buttons and state after scan completion or stop."""
        self.scan_button.config(state='normal' if self.folder_path else 'disabled')
        self.stop_button.config(state='disabled')
        self.recursive_check.config(state='normal')


if __name__ == '__main__':
    # Can't replicate but I'm keeping this
    # try:
    #     import hashlib
    # except ImportError:
    #     # hashlib is part of the standard library, but this is a safeguard
    #     tk.messagebox.showerror("Error", "Required 'hashlib' module is missing.")
    #     exit()

    root = tk.Tk()
    app = DuplicateFinderApp(root)
    root.mainloop()