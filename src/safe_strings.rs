use windows_strings::PCWSTR;
use windows_strings::PWSTR;

/// Helper function to safely execute a closure with a PCWSTR
/// The UTF-16 data is guaranteed to live for the duration of the closure
pub fn with_wide_str<F, R>(s: &str, f: F) -> R
where
    F: FnOnce(PCWSTR) -> R,
{
    let mut wide_data: Vec<u16> = s.encode_utf16().collect();
    wide_data.push(0); // Null terminate
    let pcwstr = PCWSTR::from_raw(wide_data.as_ptr());
    f(pcwstr)
}

/// Helper function to safely execute a closure with a mutable PWSTR
/// The UTF-16 data is guaranteed to live for the duration of the closure
pub fn with_wide_str_mut<F, R>(s: &str, f: F) -> R
where
    F: FnOnce(PWSTR) -> R,
{
    let mut wide_data: Vec<u16> = s.encode_utf16().collect();
    wide_data.push(0); // Null terminate
    let pwstr = PWSTR(wide_data.as_mut_ptr());
    f(pwstr)
}
