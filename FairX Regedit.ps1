Clear-Host
$colors = @("Red", "Yellow", "Cyan", "Green", "Magenta", "Blue", "White")

$asciiArt = @'
  _________                     ____  ___ __________                         .___.__  __   
 /   _____/____     ____   ____ \   \/  / \______   \ ____   ____   ____   __| _/|__|/  |_ 
 \_____  \\__  \   / ___\_/ __ \ \     /   |       _// __ \ / ___\_/ __ \ / __ | |  \   __\
 /        \/ __ \_/ /_/  >  ___/ /     \   |    |   \  ___// /_/  >  ___// /_/ | |  ||  |  
/_______  (____  /\___  / \___  >___/\  \  |____|_  /\___  >___  / \___  >____ | |__||__|  
        \/     \//_____/      \/      \_/         \/     \/_____/      \/     \/             
'@

$asciiArt -split "`n" | ForEach-Object {
    $color = Get-Random -InputObject $colors
    Write-Host $_ -ForegroundColor $color
}

$msgLines = @(
    "[+] Your Mouse is Connected With FairX Regedit",
    "[+] Sensitivity Tweaked For Maximum Precision",
    "[+] Drag Assist Enabled - Easy Headshots",
    "[+] Low Input Lag Mode ON",
    "[+] Hold LMB for Auto Drag Support",
    "[*] Press F8 to Toggle ON/OFF"
)
$msgLines | ForEach-Object {
    Write-Host $_ -ForegroundColor Red
    Start-Sleep -Milliseconds 300
}

# Show initial status line
Write-Host "`n----------------------------------------------------------------------------------"
Write-Host "Status : ON"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class FairXDragAssist {
    [DllImport("user32.dll")]
    public static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    public static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);

    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);

    public const int MOUSEEVENTF_MOVE = 0x0001;
    public const int VK_LBUTTON = 0x01;
    public const int VK_F8 = 0x77;

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X;
        public int Y;
    }

    public static bool Enabled = true;

    public static void Run() {
        POINT prev;
        GetCursorPos(out prev);
        bool isHolding = false;
        DateTime pressStart = DateTime.MinValue;

        while (true) {
            Thread.Sleep(5);
            bool toggle = (GetAsyncKeyState(VK_F8) & 0x8000) != 0;

            if (toggle && DateTime.Now.Millisecond % 2 == 0) {
                Enabled = !Enabled;

                Console.SetCursorPosition(0, Console.CursorTop - 1);
                Console.WriteLine("Status : " + (Enabled ? "ON " : "OFF"));
                Console.Beep();
                Thread.Sleep(400); // debounce
            }

            if (!Enabled)
                continue;

            bool lmbDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;

            if (lmbDown) {
                if (!isHolding) {
                    isHolding = true;
                    pressStart = DateTime.Now;
                } else if ((DateTime.Now - pressStart).TotalMilliseconds >= 60) {
                    POINT curr;
                    GetCursorPos(out curr);

                    int deltaY = curr.Y - prev.Y;
                    int deltaX = curr.X - prev.X;

                    if (deltaY < -1) {
                        int correctedX = (int)(deltaX * 0.4);
                        mouse_event(MOUSEEVENTF_MOVE, -correctedX, -4, 0, 0);
                        Thread.Sleep(10);
                    }

                    prev = curr;
                }
            } else {
                isHolding = false;
            }
        }
    }
}
"@

[FairXDragAssist]::Run()
