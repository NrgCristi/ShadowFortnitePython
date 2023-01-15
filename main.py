import subprocess
import os
import time
import requests
from ctypes import *
import sys
import crayons
import webbrowser
import aiohttp
import psutil
import json
import sys
import ctypes
from ctypes import *

PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = ( 0x00F0000 | 0x00100000 | 0xFFF )
VIRTUAL_MEM = ( 0x1000 | 0x2000 )

def cls():
	os.system('cls' if os.name == 'nt' else 'clear')

backend_url = "https://hyb.cristixpsycho.repl.co"
def start():
  try:
    path = input(f"{crayons.cyan('[+] Please Enter The Location Where Fortnite Is Installed: ', bold=True)}")
    auth_code = input(f"{crayons.cyan('[+] Please Enter The 32 Digit Code From https://rebrand.ly/authcode: ', bold=True)}")
    session = requests.Session()
    headers={
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": "basic MzQ0NmNkNzI2OTRjNGE0NDg1ZDgxYjc3YWRiYjIxNDE6OTIwOWQ0YTVlMjVhNDU3ZmI5YjA3NDg5ZDMxM2I0MWE=",
        }
    r = session.post("https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token",
        data=f"grant_type=authorization_code&code={auth_code}", headers = headers)
    d = r.json()
    
    dn = d.get('displayName')
    token_ref = d.get('access_token') 
    right = input(f"{crayons.cyan(f'[+] Logged In As {dn}, would you like to continue? (y/n)', bold=True)}")
    if right == "y":
      """yea launch fn shit"""
      args = [
        '-obfuscationid=CPq5rJkwv1mtzq9tgkidFHE_L9wZqg',
        '-AUTH_LOGIN=unused',
        f'-AUTH_PASSWORD={token_ref}',
        '-AUTH_TYPE=exchangecode',
        '-epicapp=Fortnite',
        '-epicenv=Prod',
        '-epiclocale=en-us',
        '-epicportal',
        '-nobe',
        '-noeac',
        'fltoken=919348d6add4c4c7c7507e61',
        '-skippatchcheck',
      ]
      subprocess.Popen([f'{path}/FortniteGame/Binaries/Win64/FortniteLauncher.exe'] + args, cwd=f'{path}/FortniteGame/Binaries/Win64/', stdout=subprocess.DEVNULL)

      
      proc = psutil.Process(pid = FortniteLauncher.pid)
      kernel32 = windll.kernel32
      c_ulong = ctypes.c_ulong
      pid = FortniteLauncher.pid
      
      dll_path = "/CeriumS13.dll"
      
      dll_len = len(dll_path)
      
      h_process = kernel32.OpenProcess( PROCESS_ALL_ACCESS, False, int(pid) )
      
      arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEM, PAGE_READWRITE)
      
      written = c_int(0)
      kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written))
      
      h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
      h_loadlib = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")
      
      thread_id = c_ulong(0)
      
      kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, byref(thread_id))


      
    elif right == "n":
      print("hello")
    else:
      print("hello")
  except:
    print("except")

start()