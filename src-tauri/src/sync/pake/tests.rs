use super::*;

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn scalar(value: &str) -> Scalar {
    Scalar::from_bytes_mod_order(unhex(value).try_into().expect("32 bytes"))
}

const VECTOR_CI: &str = "0b415f696e69746961746f720b425f726573706f6e646572";
const VECTOR_SID: &str = "7e4b4791d6a8ef019b936c79fb7f2c57";
const YA: &str = "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08";
const YB: &str = "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d";

#[test]
fn the_generator_matches_the_draft_vector() {
    let g = generator(b"Password", &unhex(VECTOR_CI), &unhex(VECTOR_SID));
    assert_eq!(
        hex(&g.compress().to_bytes()),
        "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56"
    );
}

#[test]
fn the_messages_shared_point_and_session_key_match_the_draft_vector() {
    let g = generator(b"Password", &unhex(VECTOR_CI), &unhex(VECTOR_SID));
    let (ya, yb) = (scalar(YA), scalar(YB));
    let point_a = (ya * g).compress().to_bytes();
    let point_b = (yb * g).compress().to_bytes();
    assert_eq!(
        hex(&point_a),
        "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157"
    );
    assert_eq!(
        hex(&point_b),
        "3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258"
    );
    let k = (yb * decode(&point_a).expect("Ya")).compress().to_bytes();
    assert_eq!(
        hex(&k),
        "80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f"
    );
    let expected = "b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dcae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c3fa2068af7900447";
    let initiator_view = shared_secret(
        &ya,
        &decode(&point_b).expect("Yb"),
        &unhex(VECTOR_SID),
        transcript(&point_a, b"ADa", &point_b, b"ADb"),
    )
    .expect("initiator");
    let responder_view = shared_secret(
        &yb,
        &decode(&point_a).expect("Ya"),
        &unhex(VECTOR_SID),
        transcript(&point_a, b"ADa", &point_b, b"ADb"),
    )
    .expect("responder");
    assert_eq!(hex(&initiator_view.isk[..]), expected);
    assert_eq!(hex(&responder_view.isk[..]), expected);
}

#[test]
fn the_draft_scalar_multiplication_and_invalid_point_vectors_hold() {
    let s = scalar("7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05");
    let x = decode(&unhex(
        "2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c",
    ))
    .expect("valid point");
    assert_eq!(
        hex(&(s * x).compress().to_bytes()),
        "7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e"
    );
    assert!(decode(&unhex(
        "2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c"
    ))
    .is_err());
    assert!(decode(&[0u8; 32]).is_err());
    assert!(decode(&[1u8; 31]).is_err());
}

fn run(
    new_device_code: &str,
    approver_code: &str,
) -> (
    Result<Completed, PakeError>,
    Result<Answered, PakeError>,
    Vec<u8>,
) {
    let offer = Offer::begin_with(
        new_device_code,
        b"new device keys",
        [7u8; SID_BYTES],
        scalar(YA),
    )
    .expect("offer");
    let (answered, new_device_ad) =
        answer_with(approver_code, &offer.message, b"approver keys", scalar(YB)).expect("answer");
    assert_eq!(new_device_ad, b"new device keys");
    let answer_message = answered.message.clone();
    let completed = offer.finish(&answer_message);
    (completed, Ok(answered), answer_message)
}

#[test]
fn the_same_code_gives_both_devices_the_same_key_and_authenticates_both_sides() {
    let (completed, answered, _) = run("abcd-efgh-jk", "ABCDEFGHJK");
    let completed = completed.expect("new device accepts the approver");
    assert_eq!(completed.approver_ad, b"approver keys");
    let key = answered
        .expect("answer")
        .verify_confirmation(&completed.confirmation)
        .expect("approver accepts the new device");
    assert_eq!(key.len(), 64);
}

#[test]
fn a_wrong_code_is_refused_by_the_new_device() {
    let (completed, _, _) = run("ABCDEFGHJK", "ABCDEFGHJM");
    assert_eq!(completed.err(), Some(PakeError::ConfirmationFailed));
}

#[test]
fn a_man_in_the_middle_without_the_code_cannot_finish() {
    let attacker_offer = Offer::begin_with("ZZZZZZZZZZ", b"attacker", [7u8; SID_BYTES], scalar(YA))
        .expect("attacker offer");
    let (answered, _) = answer_with(
        "ABCDEFGHJK",
        &attacker_offer.message,
        b"approver keys",
        scalar(YB),
    )
    .expect("approver answers whatever arrives");
    assert!(attacker_offer.finish(&answered.message).is_err());
    assert!(answered.verify_confirmation(&[0u8; TAG_BYTES]).is_err());
}

#[test]
fn a_changed_identity_in_the_answer_breaks_the_confirmation() {
    let offer = Offer::begin_with(
        "ABCDEFGHJK",
        b"new device keys",
        [7u8; SID_BYTES],
        scalar(YA),
    )
    .expect("offer");
    let (answered, _) =
        answer_with("ABCDEFGHJK", &offer.message, b"approver keys", scalar(YB)).expect("answer");
    let mut forged = answered.message.clone();
    let position = POINT_BYTES + 2;
    forged[position] ^= 1;
    assert_eq!(
        offer.finish(&forged).err(),
        Some(PakeError::ConfirmationFailed)
    );
}

#[test]
fn a_changed_identity_in_the_offer_breaks_the_confirmation() {
    let offer = Offer::begin_with(
        "ABCDEFGHJK",
        b"new device keys",
        [7u8; SID_BYTES],
        scalar(YA),
    )
    .expect("offer");
    let mut forged = offer.message.clone();
    let position = SID_BYTES + POINT_BYTES + 2;
    forged[position] ^= 1;
    let (answered, _) =
        answer_with("ABCDEFGHJK", &forged, b"approver keys", scalar(YB)).expect("answer");
    assert!(offer.finish(&answered.message).is_err());
}

#[test]
fn a_flipped_session_id_breaks_the_confirmation() {
    let offer = Offer::begin_with("ABCDEFGHJK", b"x", [7u8; SID_BYTES], scalar(YA)).expect("offer");
    let mut forged = offer.message.clone();
    forged[0] ^= 1;
    let (answered, _) = answer_with("ABCDEFGHJK", &forged, b"y", scalar(YB)).expect("answer");
    assert!(offer.finish(&answered.message).is_err());
}

#[test]
fn malformed_and_invalid_messages_are_refused_without_panicking() {
    let offer = Offer::begin_with("ABCDEFGHJK", b"x", [7u8; SID_BYTES], scalar(YA)).expect("offer");
    for length in 0..offer.message.len() {
        assert!(answer("ABCDEFGHJK", &offer.message[..length], b"y").is_err());
    }
    let mut oversized = offer.message.clone();
    oversized[SID_BYTES + POINT_BYTES] = 0xff;
    oversized[SID_BYTES + POINT_BYTES + 1] = 0xff;
    assert!(answer("ABCDEFGHJK", &oversized, b"y").is_err());
    let mut identity = offer.message.clone();
    identity[SID_BYTES..SID_BYTES + POINT_BYTES].fill(0);
    assert_eq!(
        answer("ABCDEFGHJK", &identity, b"y").err(),
        Some(PakeError::BadPoint)
    );
    let mut trailing = offer.message.clone();
    trailing.push(0);
    assert!(answer("ABCDEFGHJK", &trailing, b"y").is_err());
    assert!(Offer::begin("ABCDEFGHJK", &[0u8; MAX_AD_BYTES + 1]).is_err());
}

#[test]
fn a_bad_answer_is_refused_by_the_new_device() {
    let offer = Offer::begin_with("ABCDEFGHJK", b"x", [7u8; SID_BYTES], scalar(YA)).expect("offer");
    let (answered, _) =
        answer_with("ABCDEFGHJK", &offer.message, b"y", scalar(YB)).expect("answer");
    let mut short = answered.message.clone();
    short.pop();
    assert!(
        Offer::begin_with("ABCDEFGHJK", b"x", [7u8; SID_BYTES], scalar(YA))
            .expect("offer")
            .finish(&short)
            .is_err()
    );
    let mut identity = answered.message.clone();
    identity[..POINT_BYTES].fill(0);
    assert_eq!(offer.finish(&identity).err(), Some(PakeError::BadPoint));
}

#[test]
fn codes_use_the_alphabet_have_the_length_and_differ() {
    let first = generate_code().expect("code");
    let second = generate_code().expect("code");
    assert_eq!(first.len(), CODE_LENGTH);
    assert!(first.bytes().all(|byte| CODE_ALPHABET.contains(&byte)));
    assert_ne!(first, second);
    assert_eq!(normalize_code(" ab-cd ef"), b"ABCDEF");
    assert_eq!(normalize_code("o1il-0"), b"01110");
}

#[test]
fn random_scalars_stay_below_the_group_size() {
    for _ in 0..64 {
        let value = random_scalar().expect("scalar");
        assert!(value.as_bytes()[31] < 0x10);
    }
}
