// Live process details for Launcher.via: parent, path and arguments of a
// pid, from libproc and sysctl (the same sources as the Python monitor's
// macOS backend).
import CitadelCore
import Darwin
import Foundation

enum ProcessTable {
    static func info(_ pid: Int) -> ProcInfo? {
        guard pid > 0 else { return nil }
        var bsd = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(Int32(pid), PROC_PIDTBSDINFO, 0, &bsd, size) == size else { return nil }
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(Int32(pid), &buf, UInt32(buf.count))
        let exe = n > 0 ? String(cString: buf) : ""
        let comm = exe.isEmpty ? withUnsafeBytes(of: bsd.pbi_comm) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
                               : (exe as NSString).lastPathComponent
        return ProcInfo(pid: pid, ppid: Int(bsd.pbi_ppid), comm: comm, exe: exe, args: arguments(pid))
    }

    /// argv from KERN_PROCARGS2: argc, exec path, padding, then the arguments.
    static func arguments(_ pid: Int) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, Int32(pid)]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return [] }
        var raw = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &raw, &size, nil, 0) == 0 else { return [] }
        let argc = raw.withUnsafeBytes { Int($0.load(as: Int32.self)) }
        var i = 4
        while i < size && raw[i] != 0 { i += 1 }             // exec path
        while i < size && raw[i] == 0 { i += 1 }             // padding
        var args: [String] = []
        var start = i
        while i < size && args.count < argc {
            if raw[i] == 0 {
                args.append(String(decoding: raw[start..<i], as: UTF8.self))
                start = i + 1
            }
            i += 1
        }
        return args
    }
}
