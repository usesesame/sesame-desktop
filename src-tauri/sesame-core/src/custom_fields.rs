use crate::types::{CustomFieldEntry, LegacyField};
use crate::VaultResult;

pub struct FieldRules {
    pub kinds: &'static [&'static str],
    pub max_fields: usize,
    pub max_value_chars: usize,
    pub keeps_secret_whitespace: bool,
}

pub const RECORD_FIELDS: FieldRules = FieldRules {
    kinds: &["text", "secret", "date"],
    max_fields: 50,
    max_value_chars: 4_000,
    keeps_secret_whitespace: false,
};

pub const LOGIN_FIELDS: FieldRules = FieldRules {
    kinds: &["text", "secret"],
    max_fields: 200,
    max_value_chars: 20_000,
    keeps_secret_whitespace: true,
};

fn normalised_field(field: CustomFieldEntry, rules: &FieldRules) -> VaultResult<CustomFieldEntry> {
    let label = field.label.trim();
    if label.is_empty() {
        return Err("Give every field a label.".into());
    }
    if label.chars().count() > 160 {
        return Err("A field label is too long.".into());
    }
    if field.value.chars().count() > rules.max_value_chars {
        return Err("A field value is too long.".into());
    }
    let kind = if rules.kinds.contains(&field.kind.as_str()) {
        field.kind.clone()
    } else {
        "text".to_string()
    };
    let trimmed = field.value.trim();
    let value = if kind == "secret" && rules.keeps_secret_whitespace && !trimmed.is_empty() {
        field.value.clone()
    } else {
        trimmed.to_string()
    };
    Ok(CustomFieldEntry {
        label: label.to_string(),
        value,
        kind,
    })
}

pub fn normalised_fields(
    fields: Vec<CustomFieldEntry>,
    rules: &FieldRules,
) -> VaultResult<Vec<CustomFieldEntry>> {
    if fields.len() > rules.max_fields {
        return Err(TOO_MANY_FIELDS.into());
    }
    normalised_each(fields, rules)
}

pub const TOO_MANY_FIELDS: &str = "There are too many custom fields.";

pub fn normalised_each(
    fields: Vec<CustomFieldEntry>,
    rules: &FieldRules,
) -> VaultResult<Vec<CustomFieldEntry>> {
    fields
        .into_iter()
        .map(|field| normalised_field(field, rules))
        .collect()
}

pub fn login_field_count_allowed(count: usize, stored: usize) -> bool {
    count <= LOGIN_FIELDS.max_fields.max(stored)
}

pub fn from_legacy(fields: &[LegacyField]) -> Vec<CustomFieldEntry> {
    fields
        .iter()
        .map(|field| CustomFieldEntry {
            label: field.label.clone(),
            value: field.value.clone(),
            kind: if field.secret { "secret" } else { "text" }.to_string(),
        })
        .collect()
}

pub fn keep_field_secrets(
    fields: &mut [CustomFieldEntry],
    existing: &[CustomFieldEntry],
    kept: &[String],
) {
    for entry in kept {
        let Some(rest) = entry.strip_prefix("field:") else {
            continue;
        };
        let (new_index, old_index) = rest.split_once("<-").unwrap_or((rest, rest));
        let (Ok(new_index), Ok(old_index)) =
            (new_index.parse::<usize>(), old_index.parse::<usize>())
        else {
            continue;
        };
        let Some(previous) = existing
            .get(old_index)
            .filter(|field| field.kind == "secret")
        else {
            continue;
        };
        if let Some(field) = fields
            .get_mut(new_index)
            .filter(|field| field.kind == "secret" && field.value.is_empty())
        {
            field.value = previous.value.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(label: &str, value: &str, kind: &str) -> CustomFieldEntry {
        CustomFieldEntry {
            label: label.to_string(),
            value: value.to_string(),
            kind: kind.to_string(),
        }
    }

    #[test]
    fn login_fields_accept_only_text_and_secret() {
        let fields = normalised_fields(
            vec![
                field(" Member ", " fictional-1 ", "text"),
                field("Answer", "fictional-2", "secret"),
                field("Renewal", "2030-01-01", "date"),
                field("Other", "fictional-3", "unknown"),
            ],
            &LOGIN_FIELDS,
        )
        .expect("normalised");
        let kinds = fields
            .iter()
            .map(|field| {
                (
                    field.label.as_str(),
                    field.value.as_str(),
                    field.kind.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                ("Member", "fictional-1", "text"),
                ("Answer", "fictional-2", "secret"),
                ("Renewal", "2030-01-01", "text"),
                ("Other", "fictional-3", "text"),
            ]
        );
    }

    #[test]
    fn a_login_keeps_the_spaces_of_a_hidden_value_and_a_record_trims_them() {
        let typed = vec![
            field("Answer", " fictional answer ", "secret"),
            field("Blank", "   ", "secret"),
            field("Member", " fictional-1 ", "text"),
        ];
        let values = |rules: &FieldRules| {
            normalised_each(typed.clone(), rules)
                .expect("normalised")
                .into_iter()
                .map(|field| field.value.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            values(&LOGIN_FIELDS),
            [" fictional answer ", "", "fictional-1"]
        );
        assert_eq!(
            values(&RECORD_FIELDS),
            ["fictional answer", "", "fictional-1"]
        );
    }

    #[test]
    fn a_login_may_keep_more_fields_than_the_limit_but_not_add_to_them() {
        let limit = LOGIN_FIELDS.max_fields;
        assert!(login_field_count_allowed(limit, 0));
        assert!(!login_field_count_allowed(limit + 1, 0));
        assert!(login_field_count_allowed(limit + 5, limit + 5));
        assert!(!login_field_count_allowed(limit + 6, limit + 5));
    }

    #[test]
    fn a_field_needs_a_label_and_the_list_has_limits() {
        let long = "x".repeat(RECORD_FIELDS.max_value_chars + 1);
        assert!(normalised_fields(vec![field("Long", &long, "text")], &RECORD_FIELDS).is_err());
        assert!(normalised_fields(vec![field("Long", &long, "text")], &LOGIN_FIELDS).is_ok());
        assert!(normalised_fields(vec![field(" ", "fictional", "text")], &LOGIN_FIELDS).is_err());
        let many = (0..=LOGIN_FIELDS.max_fields)
            .map(|index| field(&format!("Field {index}"), "fictional", "text"))
            .collect();
        assert!(normalised_fields(many, &LOGIN_FIELDS).is_err());
    }

    #[test]
    fn a_kept_secret_moves_with_its_row_and_never_into_a_text_field() {
        let existing = vec![
            field("First", "fictional-first", "secret"),
            field("Second", "fictional-second", "secret"),
            field("Visible", "fictional-visible", "text"),
        ];
        let mut fields = vec![
            field("Second", "", "secret"),
            field("Now visible", "", "text"),
            field("Typed", "fictional-typed", "secret"),
            field("From text", "", "secret"),
        ];
        keep_field_secrets(
            &mut fields,
            &existing,
            &[
                "field:0<-1".to_string(),
                "field:1<-0".to_string(),
                "field:2<-0".to_string(),
                "field:3<-2".to_string(),
                "field:9<-0".to_string(),
                "password".to_string(),
            ],
        );
        assert_eq!(fields[0].value, "fictional-second");
        assert_eq!(fields[1].value, "");
        assert_eq!(fields[2].value, "fictional-typed");
        assert_eq!(fields[3].value, "");
    }
}
