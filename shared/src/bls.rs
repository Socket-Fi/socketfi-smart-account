use soroban_sdk::{bytesn, BytesN, Env};

pub fn g1_group_gen_point(env: &Env) -> BytesN<96> {
    bytesn!(
        env,0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca)
}

pub fn is_g1_infinity(key: &BytesN<96>) -> bool {
    let bytes = key.to_array();

    if bytes[0] != 0x40 {
        return false;
    }

    for b in bytes.iter().skip(1) {
        if *b != 0 {
            return false;
        }
    }

    true
}
