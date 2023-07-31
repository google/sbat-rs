use ascii::{AsciiChar, AsciiStr};

// TODO: this is similar to the `Lines` iterator in the ascii crate, but
// that type is not currently public:
// https://github.com/tomprogrammer/rust-ascii/issues/101
pub(crate) struct LineIter<'a> {
    string: &'a AsciiStr,
}

impl<'a> LineIter<'a> {
    pub(crate) fn new(string: &'a AsciiStr) -> Self {
        Self { string }
    }
}

impl<'a> Iterator for LineIter<'a> {
    type Item = &'a AsciiStr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.string.is_empty() {
            return None;
        }

        if let Some(line_end) = self
            .string
            .chars()
            .position(|chr| chr == AsciiChar::LineFeed)
        {
            let line = &self.string[..line_end];
            // OK to unwrap: we know that line_end is a valid index,
            // which means it's less than the length, which means it
            // must be less than max usize.
            self.string = &self.string[line_end.checked_add(1).unwrap()..];
            if line.last() == Some(AsciiChar::CarriageReturn) {
                // OK to unwrap: we know the line has at least one character.
                Some(&line[..line.len().checked_sub(1).unwrap()])
            } else {
                Some(line)
            }
        } else {
            let line = self.string;
            self.string = &self.string[0..0];
            Some(line)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &str) -> Vec<&AsciiStr> {
        LineIter::new(AsciiStr::from_ascii(s).unwrap()).collect::<Vec<_>>()
    }

    #[test]
    fn test_line_iter() {
        assert!(lines("").is_empty());
        assert_eq!(lines("a"), ["a"]);
        assert_eq!(lines("ab"), ["ab"]);

        assert_eq!(lines("\n"), [""]);
        assert_eq!(lines("\r\n"), [""]);
        assert_eq!(lines("\r"), ["\r"]);

        assert_eq!(lines("ab\n"), ["ab"]);
        assert_eq!(lines("ab\r\n"), ["ab"]);

        assert_eq!(lines("ab\ncd"), ["ab", "cd"]);
        assert_eq!(lines("ab\r\ncd"), ["ab", "cd"]);

        assert_eq!(lines("ab\ncd\n"), ["ab", "cd"]);
        assert_eq!(lines("ab\ncd\n\n"), ["ab", "cd", ""]);
    }
}
