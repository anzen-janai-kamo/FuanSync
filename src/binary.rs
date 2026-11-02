use crate::{Result, record::CAPACITY};
use std::ops::Range;
use zeroize::Zeroizing;

const INVALID: &str = "invalid or unsupported executable format";

fn slice(bytes: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    bytes
        .get(start..start.checked_add(len).ok_or(INVALID)?)
        .ok_or(INVALID)
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        slice(bytes, offset, 2)?.try_into().map_err(|_| INVALID)?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        slice(bytes, offset, 4)?.try_into().map_err(|_| INVALID)?,
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        slice(bytes, offset, 8)?.try_into().map_err(|_| INVALID)?,
    ))
}
fn usize64(bytes: &[u8], offset: usize) -> Result<usize> {
    usize::try_from(u64_at(bytes, offset)?).map_err(|_| INVALID)
}
fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn narrow(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| INVALID)
}
fn align(value: usize, alignment: usize) -> Result<usize> {
    if !alignment.is_power_of_two() {
        return Err(INVALID);
    }
    Ok(value.checked_add(alignment - 1).ok_or(INVALID)? & !(alignment - 1))
}
fn overlaps(a: Range<usize>, b: Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

struct Elf {
    table: usize,
    stride: usize,
    count: usize,
    strings_index: usize,
    strings: Range<usize>,
    section: Option<Range<usize>>,
    signed: bool,
}

impl Elf {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if slice(bytes, 0, 7)? != b"\x7fELF\x02\x01\x01" || u16_at(bytes, 52)? != 64 {
            return Err(INVALID);
        }
        if ![2, 3].contains(&u16_at(bytes, 16)?) {
            return Err(INVALID);
        }
        let table = usize64(bytes, 40)?;
        let stride = usize::from(u16_at(bytes, 58)?);
        let count = usize::from(u16_at(bytes, 60)?);
        let strings_index = usize::from(u16_at(bytes, 62)?);
        if stride != 64 || count == 0 || strings_index >= count || strings_index == 0 {
            return Err(INVALID);
        }
        slice(bytes, table, stride.checked_mul(count).ok_or(INVALID)?)?;
        let string_header = table + strings_index * stride;
        if u32_at(bytes, string_header + 4)? != 3 {
            return Err(INVALID);
        }
        let string_offset = usize64(bytes, string_header + 24)?;
        let string_size = usize64(bytes, string_header + 32)?;
        let strings = string_offset..string_offset.checked_add(string_size).ok_or(INVALID)?;
        let names = slice(bytes, strings.start, strings.len())?;
        let mut section = None;
        let mut signed = bytes.ends_with(b"~Module signature appended~\n");
        for index in 0..count {
            let header = table + index * stride;
            let name_start = u32_at(bytes, header)? as usize;
            let rest = names.get(name_start..).ok_or(INVALID)?;
            let end = rest.iter().position(|byte| *byte == 0).ok_or(INVALID)?;
            let name = &rest[..end];
            if [
                b".SUNW_signature".as_slice(),
                b".signature",
                b".sig",
                b".note.sig",
                b".note.signature",
                b".module_sig",
            ]
            .contains(&name)
            {
                signed = true;
            }
            if name == b".fuansync" {
                if section.is_some()
                    || u32_at(bytes, header + 4)? != 1
                    || u64_at(bytes, header + 8)? != 0
                {
                    return Err("invalid or loaded .fuansync section");
                }
                let start = usize64(bytes, header + 24)?;
                let length = usize64(bytes, header + 32)?;
                if length != CAPACITY {
                    return Err("embedded section must be exactly 1 MiB");
                }
                slice(bytes, start, length)?;
                section = Some(start..start.checked_add(length).ok_or(INVALID)?);
            }
        }
        if let Some(range) = &section {
            if overlaps(range.clone(), 0..64)
                || overlaps(range.clone(), table..table + count * stride)
                || overlaps(range.clone(), strings.clone())
            {
                return Err(INVALID);
            }
            let program_table = usize64(bytes, 32)?;
            let program_stride = usize::from(u16_at(bytes, 54)?);
            let program_count = usize::from(u16_at(bytes, 56)?);
            if program_count > 0 && program_stride != 56 {
                return Err(INVALID);
            }
            slice(bytes, program_table, program_stride * program_count)?;
            for index in 0..program_count {
                let header = program_table + index * program_stride;
                if u32_at(bytes, header)? == 1 {
                    let start = usize64(bytes, header + 8)?;
                    let size = usize64(bytes, header + 32)?;
                    if overlaps(
                        range.clone(),
                        start..start.checked_add(size).ok_or(INVALID)?,
                    ) {
                        return Err("embedded ELF section overlaps a load segment");
                    }
                }
            }
            for index in 1..count {
                let header = table + index * stride;
                if u32_at(bytes, header + 4)? != 8 {
                    let start = usize64(bytes, header + 24)?;
                    let size = usize64(bytes, header + 32)?;
                    let other = start..start.checked_add(size).ok_or(INVALID)?;
                    if other != *range && overlaps(range.clone(), other) {
                        return Err(INVALID);
                    }
                }
            }
        }
        Ok(Self {
            table,
            stride,
            count,
            strings_index,
            strings,
            section,
            signed,
        })
    }

    fn embed(&self, bytes: &[u8], record: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.signed {
            return Err("signed ELF input is not supported; re-sign the output separately");
        }
        let mut output = Zeroizing::new(bytes.to_vec());
        if let Some(section) = &self.section {
            output[section.clone()].copy_from_slice(record);
            return Ok(output);
        }
        if self.count >= 0xfeff {
            return Err("ELF section count exceeds supported limit");
        }
        let offset = align(output.len(), 8)?;
        output.resize(offset, 0);
        output.extend_from_slice(record);
        let strings_offset = output.len();
        let mut strings = bytes[self.strings.clone()].to_vec();
        let name_offset = narrow(strings.len())?;
        strings.extend_from_slice(b".fuansync\0");
        output.extend_from_slice(&strings);
        let table_offset = align(output.len(), 8)?;
        output.resize(table_offset, 0);
        output.extend_from_slice(slice(bytes, self.table, self.count * self.stride)?);
        let strings_header = table_offset + self.strings_index * self.stride;
        put64(&mut output, strings_header + 24, strings_offset as u64);
        put64(&mut output, strings_header + 32, strings.len() as u64);
        let header = output.len();
        output.resize(header + 64, 0);
        put32(&mut output, header, name_offset);
        put32(&mut output, header + 4, 1); // SHT_PROGBITS, flags zero: non-allocated.
        put64(&mut output, header + 24, offset as u64);
        put64(&mut output, header + 32, CAPACITY as u64);
        put64(&mut output, header + 48, 1);
        put64(&mut output, 40, table_offset as u64);
        put16(&mut output, 60, (self.count + 1) as u16);
        Ok(output)
    }
}

struct Pe {
    coff: usize,
    optional: usize,
    directories: usize,
    directory_count: usize,
    table: usize,
    count: usize,
    file_alignment: usize,
    section_alignment: usize,
    section: Option<Range<usize>>,
    signed: bool,
}

impl Pe {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if slice(bytes, 0, 2)? != b"MZ" {
            return Err(INVALID);
        }
        let pe = u32_at(bytes, 0x3c)? as usize;
        if slice(bytes, pe, 4)? != b"PE\0\0" {
            return Err(INVALID);
        }
        let coff = pe.checked_add(4).ok_or(INVALID)?;
        let count = usize::from(u16_at(bytes, coff + 2)?);
        let optional_size = usize::from(u16_at(bytes, coff + 16)?);
        let optional = coff + 20;
        slice(bytes, optional, optional_size)?;
        let (directory_offset, count_offset) = match u16_at(bytes, optional)? {
            0x20b => (112, 108),
            0x10b => (96, 92),
            _ => return Err(INVALID),
        };
        if optional_size < directory_offset {
            return Err(INVALID);
        }
        let directory_count = u32_at(bytes, optional + count_offset)? as usize;
        if directory_count > (optional_size - directory_offset) / 8 {
            return Err(INVALID);
        }
        let directories = optional + directory_offset;
        let table = optional + optional_size;
        if count == 0 || count >= 96 {
            return Err(INVALID);
        }
        slice(bytes, table, count * 40)?;
        let file_alignment = u32_at(bytes, optional + 36)? as usize;
        let section_alignment = u32_at(bytes, optional + 32)? as usize;
        if !(512..=65536).contains(&file_alignment)
            || !file_alignment.is_power_of_two()
            || section_alignment < file_alignment
            || !section_alignment.is_power_of_two()
        {
            return Err(INVALID);
        }
        let signed = directory_count > 4
            && (u32_at(bytes, directories + 32)? != 0 || u32_at(bytes, directories + 36)? != 0);
        let mut section = None;
        let headers_size = u32_at(bytes, optional + 60)? as usize;
        if headers_size < table + count * 40 || headers_size > bytes.len() {
            return Err(INVALID);
        }
        for index in 0..count {
            let header = table + index * 40;
            let start = u32_at(bytes, header + 20)? as usize;
            let size = u32_at(bytes, header + 16)? as usize;
            if size != 0 {
                slice(bytes, start, size)?;
                if start < headers_size {
                    return Err(INVALID);
                }
            }
            if slice(bytes, header, 8)? == b".fsync\0\0" {
                let flags = u32_at(bytes, header + 36)?;
                if section.is_some()
                    || size != CAPACITY
                    || u32_at(bytes, header + 8)? as usize != CAPACITY
                    || flags != 0x42000040
                {
                    return Err("invalid .fsync section");
                }
                section = Some(start..start.checked_add(size).ok_or(INVALID)?);
            }
        }
        if let Some(range) = &section {
            for index in 0..count {
                let header = table + index * 40;
                let start = u32_at(bytes, header + 20)? as usize;
                let size = u32_at(bytes, header + 16)? as usize;
                let other = start..start.checked_add(size).ok_or(INVALID)?;
                if other != *range && overlaps(range.clone(), other) {
                    return Err(INVALID);
                }
            }
        }
        Ok(Self {
            coff,
            optional,
            directories,
            directory_count,
            table,
            count,
            file_alignment,
            section_alignment,
            section,
            signed,
        })
    }

    fn file_offset(&self, bytes: &[u8], rva: u32, size: u32) -> Result<usize> {
        for index in 0..self.count {
            let header = self.table + index * 40;
            let start = u32_at(bytes, header + 12)?;
            let length = u32_at(bytes, header + 16)?;
            if rva >= start
                && rva.checked_add(size).ok_or(INVALID)?
                    <= start.checked_add(length).ok_or(INVALID)?
            {
                return (u32_at(bytes, header + 20)? as usize)
                    .checked_add((rva - start) as usize)
                    .ok_or(INVALID);
            }
        }
        Err(INVALID)
    }

    fn embed(&self, bytes: &[u8], record: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.signed {
            return Err("signed PE input is not supported; re-sign the output separately");
        }
        let mut output = Zeroizing::new(bytes.to_vec());
        if let Some(section) = &self.section {
            output[section.clone()].copy_from_slice(record);
            checksum(&mut output, self.optional + 64);
            return Ok(output);
        }
        let old_headers = u32_at(bytes, self.optional + 60)? as usize;
        let new_headers =
            align(self.table + (self.count + 1) * 40, self.file_alignment)?.max(old_headers);
        let shift = new_headers - old_headers;
        // Grow headers and adjust all COFF file offsets, leaving all RVAs unchanged.
        if shift > 0 {
            output.splice(old_headers..old_headers, vec![0; shift]);
            for index in 0..self.count {
                let header = self.table + index * 40;
                for field in [20, 24, 28] {
                    let value = u32_at(bytes, header + field)? as usize;
                    if value != 0 {
                        if value < old_headers {
                            return Err(INVALID);
                        }
                        put32(
                            &mut output,
                            header + field,
                            narrow(value.checked_add(shift).ok_or(INVALID)?)?,
                        );
                    }
                }
            }
            let symbols = u32_at(bytes, self.coff + 8)? as usize;
            if symbols != 0 {
                if symbols < old_headers {
                    return Err(INVALID);
                }
                put32(
                    &mut output,
                    self.coff + 8,
                    narrow(symbols.checked_add(shift).ok_or(INVALID)?)?,
                );
            }
            if self.directory_count > 6 {
                let debug_rva = u32_at(bytes, self.directories + 48)?;
                let debug_size = u32_at(bytes, self.directories + 52)?;
                if debug_size != 0 {
                    if !debug_size.is_multiple_of(28) {
                        return Err(INVALID);
                    }
                    let old_offset = self.file_offset(bytes, debug_rva, debug_size)?;
                    slice(bytes, old_offset, debug_size as usize)?;
                    for index in 0..debug_size as usize / 28 {
                        let field = old_offset + index * 28 + 24;
                        let value = u32_at(bytes, field)? as usize;
                        if value != 0 {
                            if value < old_headers {
                                return Err(INVALID);
                            }
                            put32(
                                &mut output,
                                field + shift,
                                narrow(value.checked_add(shift).ok_or(INVALID)?)?,
                            );
                        }
                    }
                }
            }
        }
        let header = self.table + self.count * 40;
        // Never overwrite header data not identified as padding.
        if output[header..header + 40].iter().any(|byte| *byte != 0) {
            return Err("PE headers contain no safe space for a new section");
        }
        let mut virtual_end = new_headers;
        for index in 0..self.count {
            let existing = self.table + index * 40;
            let address = u32_at(bytes, existing + 12)? as usize;
            let size = u32_at(bytes, existing + 8)?.max(u32_at(bytes, existing + 16)?) as usize;
            virtual_end = virtual_end.max(address.checked_add(size).ok_or(INVALID)?);
        }
        let address = align(virtual_end, self.section_alignment)?;
        let offset = align(output.len(), self.file_alignment)?;
        output.resize(offset, 0);
        output.extend_from_slice(record);
        output[header..header + 8].copy_from_slice(b".fsync\0\0");
        put32(&mut output, header + 8, CAPACITY as u32);
        put32(&mut output, header + 12, narrow(address)?);
        put32(&mut output, header + 16, CAPACITY as u32);
        put32(&mut output, header + 20, narrow(offset)?);
        put32(&mut output, header + 36, 0x42000040); // initialized/read/discardable.
        put16(&mut output, self.coff + 2, (self.count + 1) as u16);
        put32(&mut output, self.optional + 60, narrow(new_headers)?);
        put32(
            &mut output,
            self.optional + 56,
            narrow(align(
                address.checked_add(CAPACITY).ok_or(INVALID)?,
                self.section_alignment,
            )?)?,
        );
        let initialized_size = u32_at(bytes, self.optional + 8)?
            .checked_add(CAPACITY as u32)
            .ok_or(INVALID)?;
        put32(&mut output, self.optional + 8, initialized_size);
        checksum(&mut output, self.optional + 64);
        Ok(output)
    }
}

fn checksum(bytes: &mut [u8], field: usize) {
    put32(bytes, field, 0);
    let mut sum = 0u64;
    for pair in bytes.chunks(2) {
        sum += u64::from(pair[0]) + (u64::from(*pair.get(1).unwrap_or(&0)) << 8);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    put32(bytes, field, (sum as u32).wrapping_add(bytes.len() as u32));
}

pub fn embedded_record(bytes: &[u8]) -> Result<Option<&[u8]>> {
    let section = if bytes.starts_with(b"\x7fELF") {
        Elf::parse(bytes)?.section
    } else if bytes.starts_with(b"MZ") {
        Pe::parse(bytes)?.section
    } else {
        return Ok(None);
    }; // Mach-O: CLI only.
    Ok(section.map(|range| &bytes[range]))
}

pub fn embed(bytes: &[u8], record: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if record.len() != CAPACITY {
        return Err("embedded section must be exactly 1 MiB");
    }
    let output = if bytes.starts_with(b"\x7fELF") {
        Elf::parse(bytes)?.embed(bytes, record)?
    } else if bytes.starts_with(b"MZ") {
        Pe::parse(bytes)?.embed(bytes, record)?
    } else {
        return Err("embedding is supported only for ELF and PE executables");
    };
    if embedded_record(&output)? != Some(record) {
        return Err("embedded executable verification failed");
    }
    Ok(output)
}
