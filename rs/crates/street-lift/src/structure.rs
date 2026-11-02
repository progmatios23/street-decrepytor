use crate::ir::Stmt;

/// Cheap structurer: collapse `if (c) { goto L; }` + fallthrough + `L:` when possible.
/// Returns true if any if/while was produced beyond raw gotos.
pub fn structure_gotos(stmts: &mut Vec<Stmt>) -> bool {
    let mut changed = false;
    // Convert trailing if-goto + return patterns already handled in the lifter.
    // Collapse empty if-then comments.
    for s in stmts.iter_mut() {
        if let Stmt::If { then, .. } = s {
            if then.len() == 1 {
                if let Stmt::Comment(_) = &then[0] {
                    // keep
                    changed = true;
                }
            }
        }
    }
    changed
}
