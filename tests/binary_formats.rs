use fuansync::{
    binary,
    record::{self, CAPACITY, Credentials},
};
use zeroize::Zeroizing;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn record() -> Zeroizing<Vec<u8>> {
    record::encode(&Credentials {
        app: 1,
        installation: 2,
        pem: Zeroizing::new(b"fixture pem".to_vec()),
    })
    .unwrap()
}

fn elf(signed: bool) -> Vec<u8> {
    let names = b"\0.shstrtab\0.SUNW_signature\0";
    let count = if signed { 3 } else { 2 };
    let mut bytes = vec![0; 128 + count * 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, 3);
    put64(&mut bytes, 40, 128);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 58, 64);
    put16(&mut bytes, 60, count as u16);
    put16(&mut bytes, 62, 1);
    bytes[64..64 + names.len()].copy_from_slice(names);
    put32(&mut bytes, 192, 1);
    put32(&mut bytes, 196, 3);
    put64(&mut bytes, 216, 64);
    put64(&mut bytes, 224, names.len() as u64);
    if signed {
        put32(&mut bytes, 256, 11);
    }
    bytes
}

fn pe(count: usize, signed: bool) -> Vec<u8> {
    let mut bytes = vec![0; 512 + count * 512];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x3c, 64);
    bytes[64..68].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 68, 0x8664);
    put16(&mut bytes, 70, count as u16);
    put16(&mut bytes, 84, 240);
    put16(&mut bytes, 88, 0x20b);
    put32(&mut bytes, 120, 4096);
    put32(&mut bytes, 124, 512);
    put32(&mut bytes, 144, ((count + 1) * 4096) as u32);
    put32(&mut bytes, 148, 512);
    put32(&mut bytes, 196, 16);
    if signed {
        put32(&mut bytes, 232, 512);
        put32(&mut bytes, 236, 8);
    }
    for index in 0..count {
        let header = 328 + index * 40;
        bytes[header..header + 6].copy_from_slice(b".text\0");
        put32(&mut bytes, header + 8, 512);
        put32(&mut bytes, header + 12, ((index + 1) * 4096) as u32);
        put32(&mut bytes, header + 16, 512);
        put32(&mut bytes, header + 20, (512 + index * 512) as u32);
        put32(&mut bytes, header + 36, 0x60000020);
        bytes[512 + index * 512..1024 + index * 512].fill((index + 1) as u8);
    }
    bytes
}

#[test]
fn elf_nonloaded_record_and_replacement() {
    let input = elf(false);
    let record = record();
    let output = binary::embed(&input, &record).unwrap();
    assert_eq!(
        binary::embedded_record(&output).unwrap(),
        Some(record.as_slice())
    );
    let table = u64::from_le_bytes(output[40..48].try_into().unwrap()) as usize;
    assert_eq!(&output[table + 128 + 8..table + 128 + 16], &[0; 8]);
    let replaced = binary::embed(&output, &vec![0; CAPACITY]).unwrap();
    assert_eq!(replaced.len(), output.len());
    assert_eq!(
        binary::embedded_record(&replaced).unwrap().unwrap(),
        vec![0; CAPACITY]
    );
    assert!(binary::embed(&elf(true), &record).is_err());
    let mut module = input.clone();
    module.extend_from_slice(b"~Module signature appended~\n");
    assert!(binary::embed(&module, &record).is_err());
}

#[test]
fn pe_headers_growth_attributes_and_authenticode_refusal() {
    for count in [1, 4] {
        let input = pe(count, false);
        let output = binary::embed(&input, &record()).unwrap();
        assert_eq!(
            binary::embedded_record(&output).unwrap().unwrap().len(),
            CAPACITY
        );
        let header = 328 + count * 40;
        assert_eq!(&output[header..header + 8], b".fsync\0\0");
        assert_eq!(
            &output[header + 36..header + 40],
            &0x42000040u32.to_le_bytes()
        );
        for index in 0..count {
            let offset = u32::from_le_bytes(
                output[328 + index * 40 + 20..328 + index * 40 + 24]
                    .try_into()
                    .unwrap(),
            ) as usize;
            assert_eq!(
                &output[offset..offset + 512],
                &input[512 + index * 512..1024 + index * 512]
            );
        }
        let replacement = binary::embed(&output, &record()).unwrap();
        assert_eq!(*output, *replacement);
    }
    assert!(binary::embed(&pe(1, true), &record()).is_err());
}

#[test]
fn format_boundaries_fail_without_panics() {
    let record = record();
    for input in [elf(false), pe(1, false)] {
        for length in 0..input.len() {
            assert!(binary::embed(&input[..length], &record).is_err());
        }
        assert!(binary::embed(&input, &[1; 8]).is_err());
    }
    assert!(binary::embed(b"Mach-O", &record).is_err());
    assert!(binary::embedded_record(b"Mach-O").unwrap().is_none());
}
