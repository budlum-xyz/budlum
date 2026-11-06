// WP-03 lane C, BudZero side: the test target.
//
// A cargo integration test belongs to a package, and the WP-03 card names the
// BudZero workspace root (`budzero/tests/audit_lane_c.rs`) as the lock path.
// This file is the package-side target; the locks themselves live at the named
// path and are included here, so the workspace stays free of a package that
// exists only to host one test file.
include!("../../tests/audit_lane_c.rs");
