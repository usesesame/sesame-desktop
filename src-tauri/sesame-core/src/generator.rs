use zeroize::Zeroizing;

use crate::util::fill_secret;
use crate::VaultResult;

pub const MIN_CHARACTERS: u16 = 16;
pub const MAX_CHARACTERS: u16 = 64;
pub const MIN_WORDS: u16 = 5;
pub const MAX_WORDS: u16 = 10;

const CHARACTER_GROUPS: [&str; 4] = [
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "abcdefghijkmnopqrstuvwxyz",
    "23456789",
    "!@#$%^&*()-_=+",
];

const WORD_LIST: &str = include_str!("eff_wordlist.txt");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordStyle {
    Characters(u16),
    Passphrase(u16),
}

impl PasswordStyle {
    pub fn parse(style: &str, size: u16) -> Option<Self> {
        match style {
            "characters" if (MIN_CHARACTERS..=MAX_CHARACTERS).contains(&size) => {
                Some(Self::Characters(size))
            }
            "passphrase" if (MIN_WORDS..=MAX_WORDS).contains(&size) => Some(Self::Passphrase(size)),
            _ => None,
        }
    }
}

pub fn word_list() -> impl Iterator<Item = &'static str> {
    WORD_LIST.lines().filter(|word| !word.is_empty())
}

pub fn generate_password(style: PasswordStyle) -> VaultResult<Zeroizing<String>> {
    generate_with(style, &mut |buffer| fill_secret(buffer))
}

fn generate_with(
    style: PasswordStyle,
    random: &mut dyn FnMut(&mut [u8]) -> VaultResult<()>,
) -> VaultResult<Zeroizing<String>> {
    match style {
        PasswordStyle::Characters(length) => characters(usize::from(length), random),
        PasswordStyle::Passphrase(words) => passphrase(usize::from(words), random),
    }
}

fn characters(
    length: usize,
    random: &mut dyn FnMut(&mut [u8]) -> VaultResult<()>,
) -> VaultResult<Zeroizing<String>> {
    let alphabet: Vec<char> = CHARACTER_GROUPS.concat().chars().collect();
    let mut picked: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(length));
    for group in CHARACTER_GROUPS {
        let group: Vec<char> = group.chars().collect();
        picked.push(group[random_index(group.len(), random)?]);
    }
    while picked.len() < length {
        picked.push(alphabet[random_index(alphabet.len(), random)?]);
    }
    for index in (1..picked.len()).rev() {
        let swap = random_index(index + 1, random)?;
        picked.swap(index, swap);
    }
    Ok(Zeroizing::new(picked.iter().collect()))
}

fn passphrase(
    count: usize,
    random: &mut dyn FnMut(&mut [u8]) -> VaultResult<()>,
) -> VaultResult<Zeroizing<String>> {
    let words: Vec<&str> = word_list().collect();
    let mut phrase = Zeroizing::new(String::new());
    for index in 0..count {
        if index > 0 {
            phrase.push('-');
        }
        phrase.push_str(words[random_index(words.len(), random)?]);
    }
    Ok(phrase)
}

fn random_index(
    bound: usize,
    random: &mut dyn FnMut(&mut [u8]) -> VaultResult<()>,
) -> VaultResult<usize> {
    if bound == 0 || bound > u32::MAX as usize {
        return Err("Sesame could not make a password.".into());
    }
    let bound = bound as u64;
    let range = 1_u64 << 32;
    let limit = range - (range % bound);
    loop {
        let mut sample = [0_u8; 4];
        random(&mut sample)?;
        let value = u64::from(u32::from_be_bytes(sample));
        if value < limit {
            return Ok((value % bound) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_character_password_has_the_requested_length_and_every_group() {
        for length in [MIN_CHARACTERS, 20, MAX_CHARACTERS] {
            let password = generate_password(PasswordStyle::Characters(length)).expect("password");
            assert_eq!(password.chars().count(), usize::from(length));
            for group in CHARACTER_GROUPS {
                assert!(password.chars().any(|character| group.contains(character)));
            }
        }
    }

    #[test]
    fn a_passphrase_has_the_requested_number_of_listed_words() {
        let words: std::collections::HashSet<&str> = word_list().collect();
        let phrase = generate_password(PasswordStyle::Passphrase(6)).expect("phrase");
        let mut count = 0;
        let mut rest = phrase.as_str();
        while !rest.is_empty() {
            let word = words
                .iter()
                .filter(|word| rest.starts_with(**word))
                .max_by_key(|word| word.len())
                .expect("a listed word");
            count += 1;
            rest = rest[word.len()..]
                .strip_prefix('-')
                .unwrap_or(&rest[word.len()..]);
        }
        assert_eq!(count, 6);
    }

    #[test]
    fn sizes_outside_the_bounds_are_refused() {
        assert_eq!(PasswordStyle::parse("characters", 15), None);
        assert_eq!(PasswordStyle::parse("characters", 65), None);
        assert_eq!(PasswordStyle::parse("passphrase", 4), None);
        assert_eq!(PasswordStyle::parse("passphrase", 11), None);
        assert_eq!(PasswordStyle::parse("pin", 20), None);
        assert_eq!(
            PasswordStyle::parse("characters", 20),
            Some(PasswordStyle::Characters(20))
        );
        assert_eq!(
            PasswordStyle::parse("passphrase", 6),
            Some(PasswordStyle::Passphrase(6))
        );
    }

    #[test]
    fn two_passwords_differ() {
        let first = generate_password(PasswordStyle::Characters(20)).expect("first");
        let second = generate_password(PasswordStyle::Characters(20)).expect("second");
        assert_ne!(*first, *second);
    }

    #[test]
    fn samples_past_the_even_range_are_drawn_again() {
        let mut samples = vec![[0xff_u8; 4], [0, 0, 0, 7]].into_iter();
        let mut random = |buffer: &mut [u8]| {
            buffer.copy_from_slice(&samples.next().expect("sample"));
            Ok(())
        };
        assert_eq!(random_index(10, &mut random).expect("index"), 7);
    }

    #[test]
    fn a_failing_random_source_makes_no_password() {
        let mut random = |_: &mut [u8]| Err("no randomness".to_string());
        assert!(generate_with(PasswordStyle::Characters(20), &mut random).is_err());
    }

    #[test]
    fn the_word_list_matches_the_one_the_interface_uses() {
        let interface = include_str!("../../../src/lib/data/eff-wordlist.ts");
        let expected: Vec<&str> = interface
            .lines()
            .filter_map(|line| line.trim().strip_prefix('\'')?.strip_suffix("',"))
            .collect();
        let vendored: Vec<&str> = word_list().collect();
        assert_eq!(vendored.len(), 7776);
        assert_eq!(vendored, expected);
    }
}
