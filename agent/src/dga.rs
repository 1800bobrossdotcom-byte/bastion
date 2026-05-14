// DGA / random-looking-domain scoring (N3)
// ----------------------------------------------------------------------------
// Pure scoring lib — no I/O, no state. Used by the DNS detector.
//
// Heuristic: a Domain Generation Algorithm produces names like
//   `kq8z1xnv7p9wm2.com` — high Shannon entropy over the char distribution,
//   a poor vowel/consonant ratio, and (by definition) not on any reputation
//   allowlist.
//
// We classify on the second-level domain (SLD) only. TLD-stripping is
// heuristic for v1: if the last label is a 2-letter ccTLD we also strip the
// label before it as a likely public-suffix (covers `.co.uk`, `.com.au`,
// etc.). Good enough for triage; not a full PSL implementation.
//
// Returns a score plus a boolean. We deliberately keep the "suspicious"
// gate conservative — false positives on a defensive sensor erode trust
// faster than false negatives.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DgaScore {
    pub sld: String,
    pub entropy: f64,
    pub vowel_ratio: f64,
    pub length: usize,
    pub allowlisted: bool,
    pub suspicious: bool,
    pub reason: &'static str,
}

/// Common, low-noise SLDs we never want to flag. Keep small — this is not
/// a reputation database, just a tripwire de-noiser.
const ALLOWLIST: &[&str] = &[
    "google", "gstatic", "googleapis", "googleusercontent", "youtube", "ytimg",
    "apple", "icloud", "appleid", "mzstatic",
    "microsoft", "windows", "office", "live", "outlook", "msn", "bing", "msedge",
    "windowsupdate", "skype", "azure", "azureedge", "trafficmanager",
    "amazon", "amazonaws", "cloudfront", "ssl-images-amazon",
    "facebook", "fbcdn", "instagram", "whatsapp", "messenger",
    "github", "githubusercontent", "githubassets", "gitlab",
    "cloudflare", "cloudflareinsights", "akamai", "akamaized", "akamaihd",
    "fastly", "fastlylb", "jsdelivr", "unpkg", "cdnjs",
    "stackoverflow", "stackexchange", "sstatic",
    "reddit", "redditstatic", "redditmedia",
    "twitter", "twimg", "x", "tiktok", "tiktokcdn",
    "wikipedia", "wikimedia",
    "mozilla", "firefox", "addons", "ubuntu", "debian", "archlinux", "fedoraproject",
    "rust-lang", "crates", "npm", "npmjs", "nodejs", "pypi", "pythonhosted",
    "vercel", "netlify", "supabase", "openai", "anthropic", "claude",
    "letsencrypt", "digicert",
];

pub fn score(host: &str) -> DgaScore {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let sld = extract_sld(&host);
    let length = sld.chars().count();
    let entropy = shannon_entropy(&sld);
    let vowel_ratio = vowel_ratio(&sld);
    let allowlisted = ALLOWLIST.iter().any(|w| *w == sld.as_str());

    // Conservative gate: short names, allowlisted names, low-entropy names = boring.
    let (suspicious, reason) = if allowlisted {
        (false, "allowlisted")
    } else if length < 12 {
        (false, "too short to be DGA-noisy")
    } else if entropy >= 3.5 && (vowel_ratio < 0.15 || vowel_ratio > 0.85) {
        (true, "high entropy + extreme vowel ratio")
    } else if entropy >= 4.2 {
        (true, "very high entropy")
    } else {
        (false, "below threshold")
    };

    DgaScore { sld, entropy, vowel_ratio, length, allowlisted, suspicious, reason }
}

fn extract_sld(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    match labels.len() {
        0 => String::new(),
        1 => labels[0].to_string(),
        n => {
            // If last label is 2 chars (likely ccTLD) and we have >=3 labels, take n-3.
            // Otherwise take n-2.
            let idx = if labels[n - 1].len() == 2 && n >= 3 { n - 3 } else { n - 2 };
            labels[idx].to_string()
        }
    }
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, u32> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = s.chars().count() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn vowel_ratio(s: &str) -> f64 {
    let total = s.chars().filter(|c| c.is_ascii_alphabetic()).count() as f64;
    if total == 0.0 {
        return 0.0;
    }
    let vowels = s
        .chars()
        .filter(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'y'))
        .count() as f64;
    vowels / total
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allowlist_safe() {
        assert!(!score("www.google.com").suspicious);
        assert!(!score("api.github.com").suspicious);
        assert!(!score("s3.amazonaws.com").suspicious);
    }
    #[test]
    fn classic_dga_flagged() {
        assert!(score("kq8z1xnv7p9wm2.com").suspicious);
        assert!(score("xkcd1234567890abc.net").suspicious);
    }
    #[test]
    fn short_names_skipped() {
        assert!(!score("ab.cd.ef").suspicious);
    }
}
