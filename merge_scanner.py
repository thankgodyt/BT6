
import os
import uuid
import shutil

def merge_and_move_files():
    scanned_folder = "scanned"
    if not os.path.exists(scanned_folder):
        print(f"The '{scanned_folder}' folder does not exist.")
        return

    files = [f for f in os.listdir(scanned_folder) if os.path.isfile(os.path.join(scanned_folder, f))]
    
    if not files:
        print("No files to move.")
        return

    chunk_size = 25
    file_chunks = [files[i:i + chunk_size] for i in range(0, len(files), chunk_size)]

    for chunk in file_chunks:
        audit_uuid = str(uuid.uuid4())
        new_folder_path = os.path.join(scanned_folder, audit_uuid)
        
        try:
            os.makedirs(new_folder_path)
            print(f"Created folder: {new_folder_path}")

            for file_name in chunk:
                source_path = os.path.join(scanned_folder, file_name)
                destination_path = os.path.join(new_folder_path, file_name)
                shutil.move(source_path, destination_path)
                print(f"Moved '{file_name}' to '{new_folder_path}'")
            
            print(f"Successfully moved {len(chunk)} files to '{new_folder_path}'")

        except OSError as e:
            print(f"Error creating folder or moving files: {e}")

if __name__ == "__main__":
    merge_and_move_files()
