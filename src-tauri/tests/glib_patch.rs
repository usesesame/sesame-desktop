#![cfg(target_os = "linux")]

use glib::{prelude::*, translate::from_glib_none, translate::ToGlibPtr, Value, Variant};

#[test]
fn vendored_glib_patches_hold_in_optimized_builds() -> Result<(), Box<dyn std::error::Error>> {
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

    let values = [11i32.to_value(), 22i32.to_value(), 33i32.to_value()];
    let ptr: *mut glib::gobject_ffi::GValue = values.as_slice().to_glib_full();
    let copied = unsafe {
        (0..values.len())
            .map(|index| {
                let value: Value = from_glib_none(ptr.add(index));
                value.get::<i32>()
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    unsafe {
        for index in 0..values.len() {
            glib::gobject_ffi::g_value_unset(ptr.add(index));
        }
        glib::ffi::g_free(ptr.cast());
    }
    assert_eq!(copied, [11, 22, 33]);
    Ok(())
}
