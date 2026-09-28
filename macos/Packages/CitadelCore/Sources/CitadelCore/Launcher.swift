// "Started by": the launcher behind a program, for policies that cover an
// app only when a given script or program starts it. A port of describe()
// and origin() in citadel/monitor/common.py with the macOS sets; the parity
// fixture's answers come from that code.
import Foundation

public struct ProcInfo {
    public var pid: Int
    public var ppid: Int
    public var comm: String       // program name (basename of its path on macOS)
    public var exe: String        // program path
    public var args: [String]
    public init(pid: Int, ppid: Int, comm: String, exe: String, args: [String]) {
        self.pid = pid; self.ppid = ppid; self.comm = comm; self.exe = exe; self.args = args
    }
}

public struct Via: Equatable {
    public let name: String
    public let kind: String       // script | app | terminal
    public let id: String         // what policies store as `via`
}

public enum Launcher {
    public static let shells: Set<String> = ["bash", "sh", "dash", "zsh", "fish", "ksh", "env", "xargs", "timeout",
        "nohup", "setsid", "flock", "nice", "ionice", "stdbuf", "uwsm", "uwsm-app", "systemd-run", "sudo", "doas",
        "pkexec", "script", "time", "exec", "chrt"]
    public static let interpreters: Set<String> = ["bash", "sh", "dash", "zsh", "fish", "python", "python3", "node",
        "perl", "ruby", "lua", "luajit", "deno", "bun", "php", "tclsh", "osascript"]
    public static let terminals: Set<String> = ["ghostty", "alacritty", "kitty", "foot", "wezterm", "wezterm-gui",
        "konsole", "gnome-terminal-server", "xterm", "st", "tmux: server", "tmux", "zellij",
        "Terminal", "iTerm2", "Ghostty", "WezTerm", "Alacritty", "Warp", "stable"]
    public static let managers: Set<String> = ["systemd", "init", "launchd"]

    struct Described {
        let pid: Int, ppid: Int
        let comm: String, exe: String
        let name: String, kind: String, id: String
    }

    /// python3.14 -> python, node22 -> node (else unchanged)
    static func interpName(_ base: String) -> String {
        var letters = Substring(base)
        while let last = letters.last, last.isASCII && (last.isNumber || last == ".") { letters.removeLast() }
        guard !letters.isEmpty, letters.allSatisfy({ $0.isASCII && $0.isLowercase }) else { return base }
        return String(letters)
    }

    static func describe(_ p: ProcInfo) -> Described {
        let base = p.exe.isEmpty ? p.comm : (p.exe as NSString).lastPathComponent
        var kind = "app", name = base, ident = p.exe.isEmpty ? p.comm : p.exe
        if interpreters.contains(interpName(base)) && p.args.count > 1 {
            var script = ""
            var i = 1
            while i < p.args.count {
                let a = p.args[i]
                if a == "-c" || a == "-e" { break }                      // inline code: no script file
                if a == "-m" && i + 1 < p.args.count { script = p.args[i + 1]; break }
                if !a.hasPrefix("-") { script = a; break }
                i += 1
            }
            if !script.isEmpty {
                // as in the Python original, a relative script keeps the
                // interpreter's name as its id (the right side is evaluated
                // before `name` changes); policies store these ids
                ident = script.hasPrefix("/") ? script : name
                kind = "script"
                name = (script as NSString).lastPathComponent
            }
        }
        if terminals.contains(p.comm) || terminals.contains(base) { kind = "terminal" }
        return Described(pid: p.pid, ppid: p.ppid, comm: p.comm, exe: p.exe, name: name, kind: kind, id: ident)
    }

    /// The launcher responsible for `pid` (nil: started by the desktop, or by itself).
    public static func via(pid: Int, lookup: (Int) -> ProcInfo?) -> Via? {
        guard let meInfo = lookup(pid) else { return nil }
        let me = describe(meInfo)
        var found: Described? = nil
        var cur = me.ppid
        for _ in 0..<12 {
            if cur <= 1 { break }
            guard let info = lookup(cur) else { break }
            let d = describe(info)
            if managers.contains(d.comm) || d.exe.hasSuffix("/systemd") { break }
            if found == nil
                && !(shells.contains(d.comm) && d.kind != "script")
                && !(interpreters.contains(interpName(d.comm)) && d.kind != "script") {
                found = d
            }
            if d.kind == "terminal" { break }                            // started by you in a terminal
            cur = d.ppid
        }
        guard let v = found, v.id != me.id, v.name != me.name else { return nil }
        return Via(name: v.name, kind: v.kind, id: v.id)
    }
}
