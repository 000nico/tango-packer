use rand::RngCore;
use rand::rngs::OsRng;

fn create_key() -> [[u32; 4]; 2] {
    [
        [OsRng.next_u32(), OsRng.next_u32(), OsRng.next_u32(), OsRng.next_u32()],
        [OsRng.next_u32(), OsRng.next_u32(), OsRng.next_u32(), OsRng.next_u32()],
    ]
}

fn create_nonce() -> [u32; 3] {
    [OsRng.next_u32(), OsRng.next_u32(), OsRng.next_u32()]
}

fn create_state(key: [[u32; 4]; 2], nonce: [u32; 3], counter: u32) -> [[u32; 4]; 4] {
    [
        [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574],
        key[0],
        key[1],
        [counter, nonce[0], nonce[1], nonce[2]],
    ]
}

fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b); *d ^= *a; *d = d.rotate_left(16);
    *c = c.wrapping_add(*d); *b ^= *c; *b = b.rotate_left(12);
    *a = a.wrapping_add(*b); *d ^= *a; *d = d.rotate_left(8);
    *c = c.wrapping_add(*d); *b ^= *c; *b = b.rotate_left(7);
}

fn qr(s: &mut [[u32; 4]; 4], (ar, ac): (usize, usize), (br, bc): (usize, usize), (cr, cc): (usize, usize), (dr, dc): (usize, usize)) {
    let (mut a, mut b, mut c, mut d) = (s[ar][ac], s[br][bc], s[cr][cc], s[dr][dc]);
    quarter_round(&mut a, &mut b, &mut c, &mut d);
    s[ar][ac] = a; s[br][bc] = b; s[cr][cc] = c; s[dr][dc] = d;
}

fn double_round(s: &mut [[u32; 4]; 4]) {
    qr(s, (0,0), (1,0), (2,0), (3,0));
    qr(s, (0,1), (1,1), (2,1), (3,1));
    qr(s, (0,2), (1,2), (2,2), (3,2));
    qr(s, (0,3), (1,3), (2,3), (3,3));

    qr(s, (0,0), (1,1), (2,2), (3,3));
    qr(s, (0,1), (1,2), (2,3), (3,0));
    qr(s, (0,2), (1,3), (2,0), (3,1));
    qr(s, (0,3), (1,0), (2,1), (3,2));
}

fn twenty_rounds(initial: [[u32; 4]; 4]) -> [[u32; 4]; 4] {
    let mut work = initial;

    for _ in 0..10 {
        double_round(&mut work);
    }

    for i in 0..4 {
        for j in 0..4 {
            work[i][j] = work[i][j].wrapping_add(initial[i][j]);
        }
    }

    work
}

fn matrix_to_bytes(state: [[u32; 4]; 4]) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    for i in 0..4 {
        for j in 0..4 {
            let offset = (i * 4 + j) * 4;
            bytes[offset..offset + 4].copy_from_slice(&state[i][j].to_le_bytes());
        }
    }
    bytes
}

fn chacha20(message: &[u8], key: [[u32; 4]; 2], nonce: [u32; 3]) -> Vec<u8> {
    let mut output = Vec::with_capacity(message.len());
    let mut counter: u32 = 1;

    for chunk in message.chunks(64) {
        let keystream = matrix_to_bytes(twenty_rounds(create_state(key, nonce, counter)));

        for (i, byte) in chunk.iter().enumerate() {
            output.push(byte ^ keystream[i]);
        }

        counter += 1;
    }

    output
}