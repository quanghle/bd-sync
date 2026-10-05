//! `bd export` and `bd import`.

use std::io::{BufReader, Write};
use std::path::Path;

use bd_core::transfer::{ExportOptions, ImportOptions};
use bd_core::{Error, Queries, Result};

use crate::app::{App, Out};
use crate::cli::*;
use crate::io::{self, read_input};

fn path_error(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

pub fn cmd_export(app: &mut App, a: &ExportArgs) -> Result<()> {
    let opts = ExportOptions {
        include_memories: !a.no_memories,
        include_closed: !a.open_only,
        include_ephemeral: a.include_ephemeral,
    };
    let summary = match &a.output {
        // Under bd serve the file streams back to the client, which writes it.
        Some(path) if io::serving() => io::send_file(path, |w| app.read(|r| r.export_jsonl(w, &opts)))?,
        Some(path) => {
            let tmp = path.with_extension("jsonl.tmp");
            let file = std::fs::File::create(&tmp).map_err(|e| path_error(&tmp, e))?;
            let mut w = std::io::BufWriter::new(file);
            let written = app.read(|r| r.export_jsonl(&mut w, &opts)).and_then(|s| {
                // Closed before the rename, which Windows refuses for an open file.
                w.into_inner().map_err(|e| e.into_error())?;
                Ok(s)
            });
            let s = written.inspect_err(|_| {
                let _ = std::fs::remove_file(&tmp);
            })?;
            io::replace_file(&tmp, path).map_err(|e| path_error(path, e))?;
            s
        }
        None => io::with_stdout(|out| {
            let mut w = std::io::BufWriter::new(out);
            let s = app.read(|r| r.export_jsonl(&mut w, &opts))?;
            w.flush()?;
            Ok::<_, Error>(s)
        })?,
    };
    if a.output.is_some() {
        let out = Out::new(&summary).line(format!(
            "✓ Exported {} issues, {} dependencies, {} comments, {} memories (event head {})",
            summary.issues, summary.dependencies, summary.comments, summary.memories, summary.head_seq
        ));
        app.print(out);
    }
    Ok(())
}

pub fn cmd_import(app: &mut App, a: &ImportArgs) -> Result<()> {
    io::require_admin("bd import")?;
    let data = read_input(&a.file)?;
    let opts = ImportOptions { lenient: a.lenient, take_over: a.take_over };
    let dry = a.dry_run;
    let summary = app.write("import", |tx| {
        let s = tx.import_jsonl(&mut BufReader::new(data.as_bytes()), &opts)?;
        if dry {
            tx.set_rollback_only();
        }
        Ok(s)
    })?;
    let prefix = if dry { "Dry run: would import" } else { "✓ Imported" };
    let mut out = Out::new(&summary).line(format!(
        "{prefix} {} new, {} updated, {} unchanged issues; {} dependencies, {} comments, {} memories, {} leases",
        summary.created,
        summary.updated,
        summary.unchanged,
        summary.dependencies,
        summary.comments,
        summary.memories,
        summary.leases_granted
    ));
    for w in &summary.warnings {
        out = out.line(format!("  ! {w}"));
    }
    app.print(out);
    Ok(())
}
