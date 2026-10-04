// `bastion-agent maint <command>` — run maintenance without the dashboard.
//
//   maint overview                 health score + junk summary
//   maint scan                     junk categories and reclaimable size
//   maint clean [--yes] [ids...]   clean ids (default: recommended set);
//                                  without --yes it is a dry run
//   maint health                   health findings
//   maint programs                 installed programs with flags
//   maint large [min_mb]           biggest files in your profile
//   maint ... --json               raw JSON instead of a table

use anyhow::Result;

fn sev_icon(s: &str) -> &'static str {
    match s {
        "critical" => "[!!]",
        "warn" => "[! ]",
        "opportunity" => "[~ ]",
        "info" => "[i ]",
        _ => "[ok]",
    }
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn print_junk(scan: &super::junk::JunkScan) {
    println!("{:<24} {:>10} {:>9}  {}", "CATEGORY", "SIZE", "FILES", "TITLE");
    for c in &scan.categories {
        let mark = if c.default_selected { "*" } else { " " };
        let admin = if c.requires_admin { " (admin)" } else { "" };
        println!("{mark}{:<23} {:>8.2} GB {:>9}  {}{admin}", c.id, super::gb(c.bytes), c.files, c.title);
    }
    println!("\n{:.2} GB reclaimable. * = cleaned by default.", scan.total_gb);
}

fn print_findings(findings: &[crate::detectors::perf::Finding]) {
    for f in findings {
        println!("{} {:<44} {}", sev_icon(f.severity), f.title, f.current);
        if f.severity != "ok" {
            println!("       → {}", f.recommended);
        }
    }
}

pub async fn run(args: &[String]) -> Result<()> {
    let json = args.iter().any(|a| a == "--json");
    let yes = args.iter().any(|a| a == "--yes" || a == "-y");
    let rest: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let cmd = rest.first().map(|s| s.as_str()).unwrap_or("overview");

    match cmd {
        "overview" => {
            let o = super::overview().await;
            if json { return print_json(&o); }
            println!("Machine health: {}/100 ({})\n", o.score, o.grade);
            print_findings(&o.health.findings);
            println!();
            print_junk(&o.junk);
        }
        "scan" => {
            let s = super::junk::scan().await;
            if json { return print_json(&s); }
            print_junk(&s);
        }
        "clean" => {
            let ids = rest[1..].iter().map(|s| s.to_string()).collect();
            let req = super::junk::CleanRequest { ids, dry_run: !yes };
            let r = super::junk::clean(&req).await;
            if json { return print_json(&r); }
            for x in &r.results {
                println!("{:<24} {:<10} {:>8.2} GB {:>8} files  {}", x.id, x.method, super::gb(x.freed_bytes), x.deleted_files, x.message);
            }
            if r.dry_run {
                println!("\nDry run: {:.2} GB would be freed. Re-run with --yes to delete.", r.freed_gb);
            } else {
                println!("\nFreed {:.2} GB.", r.freed_gb);
            }
        }
        "health" => {
            let h = super::health::audit().await;
            if json { return print_json(&h); }
            print_findings(&h.findings);
        }
        "programs" => {
            let p = super::programs::list().await;
            if json { return print_json(&p); }
            for x in &p.programs {
                let size = x.size_mb.map(|m| format!("{m} MB")).unwrap_or_default();
                println!("{:<50} {:>10}  {:<16} {}", x.name.chars().take(50).collect::<String>(), size, x.flags.join(","), x.id);
            }
            println!("\n{} programs, {} flagged as bloatware, {:.1} GB reported install size.", p.total, p.flagged_bloatware, p.total_size_gb);
        }
        "large" => {
            let min_mb = rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(500);
            let l = super::junk::large_files(min_mb, 50).await;
            if json { return print_json(&l); }
            for f in &l.files {
                println!("{:>8} MB  {:>5} d  {}", f.size_mb, f.modified_days_ago.map(|d| d.to_string()).unwrap_or_default(), f.path);
            }
            println!("\nDownloads: {:.2} GB total, {:.2} GB older than 90 days.", super::gb(l.downloads_bytes), super::gb(l.downloads_old_bytes));
        }
        other => {
            anyhow::bail!("unknown maint command '{other}' (overview | scan | clean | health | programs | large)");
        }
    }
    Ok(())
}
