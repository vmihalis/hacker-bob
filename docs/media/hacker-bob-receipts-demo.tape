# Generate the README receipt roll from the checked-in disclosure list.
# This is a published-receipt presentation, not simulated live scan output.
# Run from the Hacker Bob repository root with: vhs docs/media/hacker-bob-receipts-demo.tape

Require bash

Output docs/media/hacker-bob-receipts-demo.gif

Set Shell bash
Set FontFamily "Menlo"
Set FontSize 17
Set Width 1200
Set Height 520
Set LineHeight 1.25
Set LetterSpacing 0
Set TypingSpeed 35ms
Set Framerate 30
Set PlaybackSpeed 1
Set LoopOffset 5%
Set CursorBlink false
Set Padding 24
Set Margin 18
Set MarginFill "#050508"
Set WindowBar RingsRight
Set BorderRadius 0
Set Theme { "name": "Hacker Bob Receipts", "black": "#050508", "red": "#FF4D4D", "green": "#68D391", "yellow": "#F5B83B", "blue": "#F5B83B", "magenta": "#F5B83B", "cyan": "#68D9D3", "white": "#F4F0E6", "brightBlack": "#575260", "brightRed": "#FF6B6B", "brightGreen": "#8BE0A8", "brightYellow": "#FFD06A", "brightBlue": "#FFD06A", "brightMagenta": "#FFD06A", "brightCyan": "#8CE9E4", "brightWhite": "#FFFFFF", "background": "#050508", "foreground": "#F4F0E6", "selection": "#2B261B", "cursor": "#F5B83B" }

Hide
Type `clear`
Enter
Show

Type `bash docs/media/hacker-bob-receipts-demo.sh`
Sleep 500ms
Enter
Wait+Screen /17 CVE IDs/
Sleep 4s
