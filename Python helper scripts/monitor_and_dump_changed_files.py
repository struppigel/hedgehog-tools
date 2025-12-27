# monitors a given folder and dumps the contents to a dump directory
# useful to obtain changed/dropped/extracted files during dynamic malware analysis 
# code modified from https://timgolden.me.uk/python/win32_how_do_i/watch_directory_for_changes.html

import os
import tempfile
import threading
import win32file
import win32con
import shutil
from datetime import datetime

FILE_CREATED = 1
FILE_DELETED = 2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5
FILE_LIST_DIRECTORY = 0x0001

def dump_file(src, dst_dir):
    filename = os.path.basename(src)
    name, ext = os.path.splitext(filename)
    timestamp = datetime.now().strftime("%Hh%Mm%Ss")
    dst_path = os.path.join(dst_dir,f"{name}_{timestamp}{ext}")
    counter = 1
    while os.path.exists(dst_path):
        new_filename = f"{name}_{timestamp}_{counter}{ext}"
        dst_path = os.path.join(dst_dir, new_filename)
        counter += 1
    shutil.copy(src, dst_path)
    return dst_path

def monitor(path_to_watch, dump_destination):
    hDir = win32file.CreateFile (
        path_to_watch,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
    )
    while True:
        results = win32file.ReadDirectoryChangesW (
            hDir,
            1024,
            True,
            win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
            win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
            win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
            win32con.FILE_NOTIFY_CHANGE_SIZE |
            win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
            win32con.FILE_NOTIFY_CHANGE_SECURITY,
            None,
            None
        )
        for action, file_name in results:
            full_filename = os.path.join (path_to_watch, file_name)
            if action == FILE_CREATED:
                print("file created", full_filename)
            elif action == FILE_DELETED:
                print("file deleted", full_filename)
            elif action == FILE_MODIFIED:
                
                #try:
                if os.path.isfile(full_filename):
                    print("file modified", full_filename)
                    print("dumping contents ...")
                    filename_dumped = dump_file(full_filename, dump_destination)
                    print("successfully dumped", filename_dumped)
                else:
                    print("folder modified", full_filename)
                #except Exception as e:
                #    print("dump failed", e)
            elif action == FILE_RENAMED_FROM:
                print("file renamed from", full_filename)
            elif action == FILE_RENAMED_TO:
                print("file renamed to", full_filename)
            else:
                print("unknown action", full_filename)
    
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python monitor_and_dump_changed_files.py <path_to_watch> <dump_directory>")
        sys.exit(1)
    
    path_to_watch = sys.argv[1]
    dump_directory = sys.argv[2]
    monitor(path_to_watch, dump_directory)