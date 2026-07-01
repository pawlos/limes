namespace TaintAnalyzer;

// Selects what a --scan run enumerates and reports.
//   Dos  — byte-source DoS shapes (today's default behaviour, unchanged).
//   Sqli — string sources gated on transitive reach to a SQL sink (CWE-89).
//   Loop — read loops with no completion check (CWE-835); structural, no taint source.
//   Recursion — self-recursion with no cycle/depth guard (CWE-674); structural, no taint source.
public enum ScanProfile { Dos, Sqli, Loop, Recursion }
