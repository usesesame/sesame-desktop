#![cfg(target_os = "linux")]

use glib::{prelude::*, Variant};

#[test]
fn string_variant_iteration_is_sound_in_optimized_builds() -> Result<(), Box<dyn std::error::Error>>
{
    let variant = Variant::array_from_iter::<String>([
        "one".to_string().to_variant(),
        "two".to_string().to_variant(),
        "three".to_string().to_variant(),
    ]);

    assert_eq!(variant.array_iter_str()?.next(), Some("one"));
    assert_eq!(variant.array_iter_str()?.nth(1), Some("two"));
    assert_eq!(variant.array_iter_str()?.last(), Some("three"));
    assert_eq!(variant.array_iter_str()?.next_back(), Some("three"));
    assert_eq!(variant.array_iter_str()?.nth_back(1), Some("two"));
    Ok(())
}
