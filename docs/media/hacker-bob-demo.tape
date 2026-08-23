# Generate the README installation demo from a disposable local workspace.
# Run from the Hacker Bob repository root with: vhs docs/media/hacker-bob-demo.tape

Require node
Require npm
Require grep

Output docs/media/hacker-bob-demo.gif

Set Shell bash
Set FontFamily "Menlo"
Set FontSize 20
Set Width 1200
Set Height 520
Set LineHeight 1.2
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
Set Theme { "name": "Hacker Bob", "black": "#050508", "red": "#FF5C57", "green": "#68D391", "yellow": "#F5B83B", "blue": "#F5B83B", "magenta": "#F5B83B", "cyan": "#68D9D3", "white": "#F4F0E6", "brightBlack": "#575260", "brightRed": "#FF7B77", "brightGreen": "#8BE0A8", "brightYellow": "#FFD06A", "brightBlue": "#FFD06A", "brightMagenta": "#FFD06A", "brightCyan": "#8CE9E4", "brightWhite": "#FFFFFF", "background": "#050508", "foreground": "#F4F0E6", "selection": "#2B261B", "cursor": "#F5B83B" }

Hide
Type `export BOB_DEMO_SOURCE="$PWD"`
Enter
Type `export BOB_DEMO_ROOT="/private/tmp/hacker-bob-vhs-install-demo"`
Enter
Type `rm -rf "$BOB_DEMO_ROOT" && mkdir -p "$BOB_DEMO_ROOT/project" "$BOB_DEMO_ROOT/home"`
Enter
Type `test -d node_modules || npm ci --silent`
Enter
Sleep 30s
Type `export HOME="$BOB_DEMO_ROOT/home"`
Enter
Type `alias hacker-bob="node $BOB_DEMO_SOURCE/bin/hacker-bob.js"`
Enter
Type `cd "$BOB_DEMO_ROOT" && clear`
Enter
Show

Type `hacker-bob install ./project --adapter claude 2>&1 | grep -E '^(Installing|  host adapter|  MCP runtime|Dependency check:|Done\.)'`
Sleep 500ms
Enter
Wait+Screen /Done\./
Sleep 4s

Hide
Type `rm -rf "$BOB_DEMO_ROOT"`
Enter
