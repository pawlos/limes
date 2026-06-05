namespace TaintAnalyzer;

// Selects what a --scan run enumerates and reports.
//   Dos  — byte-source DoS shapes (today's default behaviour, unchanged).
//   Sqli — string sources gated on transitive reach to a SQL sink (CWE-89).
public enum ScanProfile { Dos, Sqli }
