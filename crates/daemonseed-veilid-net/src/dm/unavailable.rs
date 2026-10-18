//! Why direct messaging cannot run, in a form a front end can show.
//!
//! [`DmUnavailable`] pairs the [`DmUnavailableCause`] a front end words its
//! notice from with the text of the error behind it, which a user can copy and
//! hand to a developer. That text is redacted when the value is built, by
//! [`redact_detail`]. An absolute, home-relative or Windows path that begins a
//! word becomes `<path>`, as does the home directory named by `HOME` or
//! `USERPROFILE` wherever it appears. A run of at least 32 hex or base64
//! characters becomes `<redacted>` where it holds a digit, is all hex, mixes
//! upper and lower case, or holds 40 letters and digits in a row.
//! [`DmUnavailable::with_redactions`] also replaces strings the caller names,
//! such as a relative profile root, which none of those rules finds, where
//! each stands as a whole path component. The redaction is best effort: text
//! that matches none of these rules is kept.

/// What replaces a filesystem path in a [`DmUnavailable`]'s detail.
pub const REDACTED_PATH: &str = "<path>";

/// What replaces a long key-like token in a [`DmUnavailable`]'s detail.
pub const REDACTED_TOKEN: &str = "<redacted>";

/// The shortest run of hex or base64 characters [`redact_detail`] treats as
/// key material, where the run also holds a digit, is all hex, or mixes upper
/// and lower case.
const TOKEN_MIN_LEN: usize = 32;

/// The shortest stretch of letters and digits [`redact_detail`] treats as key
/// material whatever its case, longer than any word an error message uses.
const ALNUM_TOKEN_MIN_LEN: usize = 40;

/// Why direct messaging cannot run, as the user is told it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DmUnavailableCause {
    /// This connection has no Veilid node, so there is nothing to run over.
    NotConnected,
    /// The direct-message record store could not be opened or built, or the
    /// profile has no root to hold it.
    StoreUnopened,
    /// The runner ended with an error.
    RunnerFailed,
    /// An internal failure: the runner panicked, its start or end task
    /// panicked, or the direct-message keys did not derive.
    Internal,
}

/// Why direct messaging cannot run, with the redacted text of the error
/// behind it.
///
/// The detail is private so that every value goes through [`Self::new`] or
/// [`Self::with_redactions`], which redact it. A value whose cause is
/// [`DmUnavailableCause::NotConnected`] holds no detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmUnavailable {
    cause: DmUnavailableCause,
    detail: String,
}

impl DmUnavailable {
    /// `cause`, with `detail` redacted by [`redact_detail`]. The detail is
    /// dropped where the cause is [`DmUnavailableCause::NotConnected`], which
    /// names no error.
    pub fn new(cause: DmUnavailableCause, detail: &str) -> Self {
        Self::with_redactions(cause, detail, &[])
    }

    /// [`Self::new`], with each of `literals` in `detail` also replaced by
    /// [`REDACTED_PATH`] before [`redact_detail`] runs: a profile root given as
    /// a relative path, and its canonical form, are strings no rule of
    /// [`redact_detail`] finds. A literal is replaced only where it stands as a
    /// whole path component: it begins the text, or follows whitespace, a path
    /// separator or a character that begins a word for [`redact_detail`], and
    /// it ends the text, or is followed by a path separator, whitespace, a
    /// quote, a backtick, a closing bracket, a comma or a semicolon. A longer
    /// literal is replaced before a shorter one, so a literal inside another
    /// does not split it. Path separators that end a literal, as a root given
    /// as `alice-profile/` has, are dropped before it is matched. A literal
    /// shorter than two characters, or made only of dots, is skipped, since
    /// replacing it would rewrite ordinary text.
    pub fn with_redactions(cause: DmUnavailableCause, detail: &str, literals: &[&str]) -> Self {
        let detail = match cause {
            DmUnavailableCause::NotConnected => String::new(),
            _ => redact_detail(&redact_literals(detail, literals)),
        };
        Self { cause, detail }
    }

    /// Why messaging cannot run.
    pub fn cause(&self) -> DmUnavailableCause {
        self.cause
    }

    /// The redacted error text: empty where the cause is
    /// [`DmUnavailableCause::NotConnected`].
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The error text a front end shows beneath its notice: `None` where the
    /// cause is [`DmUnavailableCause::NotConnected`], which names no error, or
    /// where there is no text.
    pub fn shown_detail(&self) -> Option<&str> {
        match self.cause {
            DmUnavailableCause::NotConnected => None,
            _ if self.detail.trim().is_empty() => None,
            _ => Some(&self.detail),
        }
    }
}

/// `text` with every absolute filesystem path replaced by [`REDACTED_PATH`]
/// and every long key-like token by [`REDACTED_TOKEN`].
///
/// A path is recognised where it begins a word: `/…` (Unix), `~/…` or `~\…`
/// (a home directory), `X:\…` or `X:/…` (a Windows drive), `\\…` (a Windows
/// share) or `\…` (a Windows rooted path). A word begins at the start of the
/// text or after whitespace, an opening bracket, a quote, a backtick, `=`,
/// `:`, `,` or `;`. A path runs to the next whitespace, quote, backtick,
/// comma, semicolon or closing bracket, and on across a space where the next
/// word holds a separator too, so a directory name with a space in it is not
/// cut in half. Trailing `.` and `:` are kept as punctuation. The home
/// directory named by `HOME` or `USERPROFILE` is then replaced wherever it
/// still appears.
///
/// A key-like token is a run of at least 32 characters from the hex and
/// base64 alphabets (`A-Z a-z 0-9 + / = _ -`) that holds a digit, is all hex
/// digits, holds both upper- and lower-case letters, or holds at least 40
/// letters and digits in a row. A shorter run of one case without a digit,
/// such as a long word or words joined by hyphens, is kept.
pub fn redact_detail(text: &str) -> String {
    let mut out = redact_paths(text);
    for var in ["HOME", "USERPROFILE"] {
        if let Some(home) = std::env::var_os(var) {
            let home = home.to_string_lossy();
            let home = home.trim_end_matches(['/', '\\']);
            if home.len() > 1 {
                out = out.replace(home, REDACTED_PATH);
            }
        }
    }
    redact_tokens(&out)
}

/// `text` with each of `literals`, less the path separators that end it, of
/// two characters or more, other than one made only of dots, replaced by
/// [`REDACTED_PATH`] where it stands as a whole path component, longest first.
fn redact_literals(text: &str, literals: &[&str]) -> String {
    let mut literals: Vec<&str> = literals
        .iter()
        .map(|literal| literal.trim_end_matches(['/', '\\']))
        .filter(|literal| literal.chars().count() > 1 && !literal.chars().all(|c| c == '.'))
        .collect();
    literals.sort_by_key(|literal| std::cmp::Reverse(literal.len()));
    let mut out = text.to_owned();
    for literal in literals {
        out = replace_components(&out, literal);
    }
    out
}

/// `text` with `literal` replaced by [`REDACTED_PATH`] wherever it stands as a
/// whole path component (see [`DmUnavailable::with_redactions`]).
fn replace_components(text: &str, literal: &str) -> String {
    let separator = |c: char| c == '/' || c == '\\';
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        let rest = &text[i..];
        let starts = text[..i].chars().next_back().is_none_or(|prev| {
            prev.is_whitespace() || separator(prev) || "([{<\"'`=:,;".contains(prev)
        });
        let ends = || {
            rest[literal.len()..]
                .chars()
                .next()
                .is_none_or(|next| separator(next) || ends_path(next))
        };
        if starts && rest.starts_with(literal) && ends() {
            out.push_str(REDACTED_PATH);
            i += literal.len();
        } else {
            let c = rest.chars().next().expect("i is inside the text");
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

/// Whether a path may begin at `chars[i]`: at the start of the text, or after
/// whitespace or a character that opens or introduces a value.
fn at_word_start(chars: &[char], i: usize) -> bool {
    i == 0 || {
        let prev = chars[i - 1];
        prev.is_whitespace() || "([{<\"'`=:,;".contains(prev)
    }
}

/// Whether an absolute path begins at `chars[i]`.
fn path_starts(chars: &[char], i: usize) -> bool {
    let at = |k: usize| chars.get(i + k).copied();
    let separator = |c: Option<char>| matches!(c, Some('/' | '\\'));
    match at(0) {
        Some('/' | '\\') => at(1).is_some_and(|next| !next.is_whitespace()),
        Some('~') => separator(at(1)),
        Some(drive) if drive.is_ascii_alphabetic() => at(1) == Some(':') && separator(at(2)),
        _ => false,
    }
}

/// Whether `c` ends a path.
fn ends_path(c: char) -> bool {
    c.is_whitespace() || "\"'`)]}>,;".contains(c)
}

/// The index one past the end of the path that begins at `chars[start]`.
fn path_end(chars: &[char], start: usize) -> usize {
    let mut end = start;
    loop {
        while end < chars.len() && !ends_path(chars[end]) {
            end += 1;
        }
        // Carry on over a single space where the next word holds a separator
        // too: a directory name with a space in it.
        if end < chars.len() && chars[end] == ' ' {
            let next = end + 1;
            let mut word_end = next;
            while word_end < chars.len() && !ends_path(chars[word_end]) {
                word_end += 1;
            }
            if chars[next..word_end].iter().any(|&c| c == '/' || c == '\\') {
                end = word_end;
                continue;
            }
        }
        break;
    }
    while end > start + 1 && matches!(chars[end - 1], '.' | ':') {
        end -= 1;
    }
    end
}

/// `text` with every absolute path replaced by [`REDACTED_PATH`].
fn redact_paths(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if at_word_start(&chars, i) && path_starts(&chars, i) {
            out.push_str(REDACTED_PATH);
            i = path_end(&chars, i);
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Whether `c` belongs to the hex or base64 alphabets.
fn key_alphabet(c: char) -> bool {
    c.is_ascii_alphanumeric() || "+/=_-".contains(c)
}

/// Whether `run`, a run of key-alphabet characters, reads as key material: at
/// least [`TOKEN_MIN_LEN`] long, and holding a digit, all hex digits, both
/// upper- and lower-case letters, or [`ALNUM_TOKEN_MIN_LEN`] letters and digits
/// in a row.
fn key_like(run: &[char]) -> bool {
    run.len() >= TOKEN_MIN_LEN
        && (run.iter().any(char::is_ascii_digit)
            || run.iter().all(char::is_ascii_hexdigit)
            || (run.iter().any(char::is_ascii_uppercase)
                && run.iter().any(char::is_ascii_lowercase))
            || run
                .split(|c| !c.is_ascii_alphanumeric())
                .any(|stretch| stretch.len() >= ALNUM_TOKEN_MIN_LEN))
}

/// `text` with every long key-like token replaced by [`REDACTED_TOKEN`].
fn redact_tokens(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if !key_alphabet(chars[i]) {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && key_alphabet(chars[i]) {
            i += 1;
        }
        let run = &chars[start..i];
        if key_like(run) {
            out.push_str(REDACTED_TOKEN);
        } else {
            out.extend(run);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unix and Windows paths under a user's home directory are replaced, and
    /// the user's name survives in neither.
    #[test]
    fn home_paths_in_both_forms_are_redacted() {
        let text = "dm store lock: /home/alice/.local/share/daemonseed/dm/lock is a symlink; \
                    also C:\\Users\\alice\\AppData\\Roaming\\daemonseed\\dm\\block-list.bin: \
                    access denied";
        let out = redact_detail(text);
        assert!(!out.contains("alice"), "a user name survived: {out}");
        assert!(!out.contains("/home"), "a Unix path survived: {out}");
        assert!(!out.contains("C:\\"), "a Windows path survived: {out}");
        assert!(!out.contains("AppData"), "a Windows path survived: {out}");
        assert_eq!(
            out,
            "dm store lock: <path> is a symlink; also <path>: access denied"
        );
    }

    /// Paths are found after the punctuation an error message puts before
    /// them, in every form, and a space inside a directory name does not end
    /// one early.
    #[test]
    fn every_path_form_is_found_where_an_error_puts_it() {
        let cases = [
            ("open (/var/lib/x) failed", "open (<path>) failed"),
            ("path=/tmp/a.bin.", "path=<path>."),
            ("\"/etc/passwd\" refused", "\"<path>\" refused"),
            ("at ~/daemonseed/dm", "at <path>"),
            ("at ~\\daemonseed\\dm", "at <path>"),
            ("on D:/profiles/bob/dm, retrying", "on <path>, retrying"),
            ("share \\\\server\\bob\\dm gone", "share <path> gone"),
            ("rooted \\Users\\bob\\dm gone", "rooted <path> gone"),
            (
                "C:\\Users\\alice smith\\AppData\\dm denied",
                "<path> denied",
            ),
            ("/home/alice/x: not found", "<path>: not found"),
        ];
        for (text, want) in cases {
            assert_eq!(redact_detail(text), want, "for {text:?}");
        }
    }

    /// A slash or colon inside ordinary prose is not a path.
    #[test]
    fn prose_with_slashes_is_left_alone() {
        for text in [
            "dm store I/O failed on block-list.bin: permission denied",
            "subkey count 0 is outside 1..=255",
            "the runner panicked",
            "read and/or write failed",
            "a 9000-byte ciphertext does not fit a 1024-byte subkey",
        ] {
            assert_eq!(redact_detail(text), text);
        }
    }

    /// A long hex or base64 run reads as key material and is replaced; a long
    /// word without a digit is not.
    #[test]
    fn key_like_tokens_are_redacted() {
        let hex = "a3".repeat(32);
        let out = redact_detail(&format!("record {hex} did not open"));
        assert_eq!(out, "record <redacted> did not open");
        let veilid = "VLD0:jbX7nQ2s1kR8e0Lw-Zp4H_tYc9uVfD3oGmAqSiNxKyE";
        assert_eq!(redact_detail(veilid), "VLD0:<redacted>");
        let word = "supercalifragilisticexpialidocious";
        assert!(word.len() >= TOKEN_MIN_LEN);
        assert_eq!(redact_detail(word), word);
    }

    /// A run of one case without a digit is key material once it holds 40
    /// letters and digits in a row, as a single-case base64 key can; one
    /// letter short of that it is kept.
    #[test]
    fn a_single_case_run_of_forty_letters_is_redacted() {
        let lower = "qwertyuiopasdfghjklzxcvbnm".repeat(2);
        let key = &lower[..ALNUM_TOKEN_MIN_LEN];
        assert!(!key.contains(|c: char| c.is_ascii_digit() || c.is_ascii_uppercase()));
        assert!(!key.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            redact_detail(&format!("key {key}= refused")),
            "key <redacted> refused"
        );
        let upper = key.to_ascii_uppercase();
        assert_eq!(redact_detail(&upper), "<redacted>");
        let short = &lower[..ALNUM_TOKEN_MIN_LEN - 1];
        assert_eq!(redact_detail(short), short, "control: 39 letters are kept");
    }

    /// A long run without a digit is still key material where it is all hex
    /// or mixes upper and lower case, as base64 and base64url keys do.
    #[test]
    fn digitless_hex_and_mixed_case_runs_are_redacted() {
        let hex = "deadbeefcafe".repeat(3);
        assert!(hex.len() >= TOKEN_MIN_LEN && !hex.contains(|c: char| c.is_ascii_digit()));
        assert_eq!(
            redact_detail(&format!("record {hex} did not open")),
            "record <redacted> did not open"
        );
        let upper_hex = hex.to_ascii_uppercase();
        assert_eq!(redact_detail(&upper_hex), "<redacted>");
        let base64url = "jbXnQsKReLwZpHtYcuVfDoGmAqSiNxKyE-_w";
        assert!(base64url.len() >= TOKEN_MIN_LEN);
        assert!(!base64url.contains(|c: char| c.is_ascii_digit()));
        assert_eq!(
            redact_detail(&format!("key {base64url}: refused")),
            "key <redacted>: refused"
        );
        let base64 = "AbCdEfGhIjKlMnOpQrStUvWxYz+/AbCdEf==";
        assert!(!base64.contains(|c: char| c.is_ascii_digit()));
        assert_eq!(redact_detail(base64), "<redacted>");
    }

    /// Ordinary words survive, however long the sentence and whatever their
    /// case: each word is its own run, shorter than a key, and words joined by
    /// hyphens make a run of one case without a digit, in which no stretch of
    /// letters reaches 40.
    #[test]
    fn a_long_sentence_of_ordinary_words_survives() {
        let text = "The Direct Message Store Could Not Be Opened Because Another \
                    Process Already Holds Its Lock, and retrying later is the \
                    recommended course of action for a well-behaved client-side \
                    application";
        assert_eq!(redact_detail(text), text);
        let hyphenated = "a-very-long-hyphenated-lowercase-phrase-without-digits";
        assert!(hyphenated.len() >= TOKEN_MIN_LEN);
        assert_eq!(redact_detail(hyphenated), hyphenated);
    }

    /// The home directory is replaced wherever it appears, even where it does
    /// not begin a word.
    #[test]
    fn the_home_directory_is_replaced_anywhere() {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };
        let home = home.to_string_lossy().into_owned();
        if home.trim_end_matches('/').len() <= 1 {
            return;
        }
        let out = redact_detail(&format!("file{home}/x"));
        assert!(!out.contains(&home), "{out}");
    }

    /// The constructor redacts, so no value carries a path.
    #[test]
    fn a_built_value_carries_no_path() {
        let why = DmUnavailable::new(
            DmUnavailableCause::RunnerFailed,
            "direct-message store: /home/alice/dm/lock is a symlink",
        );
        assert_eq!(why.cause(), DmUnavailableCause::RunnerFailed);
        assert_eq!(why.detail(), "direct-message store: <path> is a symlink");
    }

    /// The literals a caller names are replaced before the other rules run: a
    /// relative profile root as given and its canonical form, neither of which
    /// the path rules find on their own.
    #[test]
    fn named_literals_are_redacted_before_the_rules() {
        let text = "direct-message store: alice-profile/dm/lock is a symlink, \
                    at /srv/users/alice-profile/dm/lock";
        assert!(
            redact_detail(text).contains("alice-profile"),
            "the rules alone keep a relative root"
        );
        let why = DmUnavailable::with_redactions(
            DmUnavailableCause::StoreUnopened,
            text,
            &["alice-profile", "/srv/users/alice-profile"],
        );
        assert!(!why.detail().contains("alice"), "{}", why.detail());
        assert_eq!(
            why.detail(),
            "direct-message store: <path>/dm/lock is a symlink, at <path>/dm/lock"
        );
        let short = DmUnavailable::with_redactions(
            DmUnavailableCause::RunnerFailed,
            "the runner ended",
            &[".", ""],
        );
        assert_eq!(
            short.detail(),
            "the runner ended",
            "a one-character literal is skipped"
        );
    }

    /// A literal that ends in path separators, as a root completed by a shell
    /// does, is matched without them.
    #[test]
    fn a_literal_ending_in_a_separator_is_still_redacted() {
        let redact = |literal: &str| {
            DmUnavailable::with_redactions(
                DmUnavailableCause::StoreUnopened,
                "direct-message store: alice-profile/dm/lock is a symlink",
                &[literal],
            )
            .detail()
            .to_owned()
        };
        let redacted = "direct-message store: <path>/dm/lock is a symlink";
        assert_eq!(redact("alice-profile"), redacted, "control: the bare root");
        assert_eq!(redact("alice-profile/"), redacted);
        assert_eq!(redact("alice-profile\\//"), redacted);
        assert_eq!(
            redact("/"),
            "direct-message store: alice-profile/dm/lock is a symlink",
            "a literal of separators alone is skipped"
        );
    }

    /// A longer literal is replaced before a shorter one inside it, so the
    /// shorter does not split it.
    #[test]
    fn a_longer_literal_is_replaced_first() {
        let redact = |literals: &[&str]| {
            DmUnavailable::with_redactions(
                DmUnavailableCause::StoreUnopened,
                "open alice/dm/lock failed",
                literals,
            )
            .detail()
            .to_owned()
        };
        assert_eq!(
            redact(&["alice"]),
            "open <path>/dm/lock failed",
            "control: the shorter literal alone splits the longer"
        );
        assert_eq!(redact(&["alice", "alice/dm"]), "open <path>/lock failed");
        assert_eq!(redact(&["alice/dm", "alice"]), "open <path>/lock failed");
    }

    /// A literal is replaced only where it stands as a whole path component,
    /// so a short or common root leaves the words around it alone, and a
    /// literal made only of dots is skipped.
    #[test]
    fn a_literal_is_replaced_only_as_a_whole_component() {
        let redact = |text: &str, literal: &str| {
            DmUnavailable::with_redactions(DmUnavailableCause::StoreUnopened, text, &[literal])
                .detail()
                .to_owned()
        };
        assert_eq!(
            redact("direct-message store: store/dm/lock is a symlink", "store"),
            "direct-message store: <path>/dm/lock is a symlink"
        );
        assert_eq!(
            redact("admin owns dm/lock and dm", "dm"),
            "admin owns <path>/lock and <path>"
        );
        assert_eq!(
            redact("open \"dm\\lock\" (at dm), retrying", "dm"),
            "open \"<path>\\lock\" (at <path>), retrying"
        );
        assert_eq!(redact("redb failed for dm/x", "db"), "redb failed for dm/x");
        assert_eq!(
            redact("waited... then ../x failed", ".."),
            "waited... then ../x failed"
        );
    }

    /// A value whose cause is [`DmUnavailableCause::NotConnected`] holds no
    /// detail, from either constructor.
    #[test]
    fn not_connected_holds_no_detail() {
        let why = DmUnavailable::new(DmUnavailableCause::NotConnected, "no Veilid node");
        assert_eq!(why.detail(), "");
        let why = DmUnavailable::with_redactions(
            DmUnavailableCause::NotConnected,
            "no Veilid node",
            &["node"],
        );
        assert_eq!(why.detail(), "");
        assert_eq!(why.cause(), DmUnavailableCause::NotConnected);
    }

    /// Not being connected shows no detail; every other cause shows its text,
    /// unless there is none.
    #[test]
    fn only_a_cause_with_an_error_shows_its_detail() {
        let shown = |cause, detail: &str| {
            DmUnavailable::new(cause, detail)
                .shown_detail()
                .map(str::to_owned)
        };
        assert_eq!(
            shown(DmUnavailableCause::NotConnected, "no Veilid node"),
            None
        );
        assert_eq!(shown(DmUnavailableCause::RunnerFailed, "  "), None);
        for cause in [
            DmUnavailableCause::StoreUnopened,
            DmUnavailableCause::RunnerFailed,
            DmUnavailableCause::Internal,
        ] {
            assert_eq!(shown(cause, "boom").as_deref(), Some("boom"));
        }
    }
}
