//! Minimal NBT reader/writer used to add the Gorizont server to Minecraft's multiplayer list (servers.dat).
use std::{fs, io, path::Path};

#[derive(Debug, Clone, PartialEq)]
pub enum Nbt {
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    ByteArray(Vec<u8>),
    String(String),
    List(u8, Vec<Nbt>),
    Compound(Vec<(String, Nbt)>),
    IntArray(Vec<i32>),
    LongArray(Vec<i64>),
}

impl Nbt {
    fn id(&self) -> u8 {
        match self {
            Nbt::Byte(_) => 1, Nbt::Short(_) => 2, Nbt::Int(_) => 3, Nbt::Long(_) => 4, Nbt::Float(_) => 5, Nbt::Double(_) => 6,
            Nbt::ByteArray(_) => 7, Nbt::String(_) => 8, Nbt::List(..) => 9, Nbt::Compound(_) => 10, Nbt::IntArray(_) => 11, Nbt::LongArray(_) => 12,
        }
    }
}

struct Reader<'a> { data: &'a [u8], pos: usize }

fn bad(msg: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, msg.to_string()) }

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.pos + n > self.data.len() { return Err(bad("unexpected end of NBT")); }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }
    fn u8(&mut self) -> io::Result<u8> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> io::Result<u16> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn i32(&mut self) -> io::Result<i32> { Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn i64(&mut self) -> io::Result<i64> { Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn string(&mut self) -> io::Result<String> { let len = self.u16()? as usize; Ok(String::from_utf8_lossy(self.take(len)?).into_owned()) }
    fn len(&mut self) -> io::Result<usize> { let n = self.i32()?; if n < 0 { Err(bad("negative length")) } else { Ok(n as usize) } }

    fn payload(&mut self, id: u8, depth: u32) -> io::Result<Nbt> {
        if depth > 64 { return Err(bad("NBT nested too deeply")); }
        Ok(match id {
            1 => Nbt::Byte(self.u8()? as i8),
            2 => Nbt::Short(self.u16()? as i16),
            3 => Nbt::Int(self.i32()?),
            4 => Nbt::Long(self.i64()?),
            5 => Nbt::Float(f32::from_bits(self.i32()? as u32)),
            6 => Nbt::Double(f64::from_bits(self.i64()? as u64)),
            7 => { let n = self.len()?; Nbt::ByteArray(self.take(n)?.to_vec()) }
            8 => Nbt::String(self.string()?),
            9 => {
                let item = self.u8()?; let n = self.len()?;
                if item == 0 && n > 0 { return Err(bad("list of End tags")); }
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n { items.push(self.payload(item, depth + 1)?); }
                Nbt::List(item, items)
            }
            10 => {
                let mut entries = Vec::new();
                loop {
                    let tag = self.u8()?;
                    if tag == 0 { break; }
                    let name = self.string()?;
                    entries.push((name, self.payload(tag, depth + 1)?));
                }
                Nbt::Compound(entries)
            }
            11 => { let n = self.len()?; let mut v = Vec::with_capacity(n.min(1024)); for _ in 0..n { v.push(self.i32()?); } Nbt::IntArray(v) }
            12 => { let n = self.len()?; let mut v = Vec::with_capacity(n.min(1024)); for _ in 0..n { v.push(self.i64()?); } Nbt::LongArray(v) }
            _ => return Err(bad("unknown NBT tag")),
        })
    }
}

fn write_string(out: &mut Vec<u8>, s: &str) { out.extend_from_slice(&(s.len() as u16).to_be_bytes()); out.extend_from_slice(s.as_bytes()); }

fn write_payload(out: &mut Vec<u8>, tag: &Nbt) {
    match tag {
        Nbt::Byte(v) => out.push(*v as u8),
        Nbt::Short(v) => out.extend_from_slice(&v.to_be_bytes()),
        Nbt::Int(v) => out.extend_from_slice(&v.to_be_bytes()),
        Nbt::Long(v) => out.extend_from_slice(&v.to_be_bytes()),
        Nbt::Float(v) => out.extend_from_slice(&v.to_bits().to_be_bytes()),
        Nbt::Double(v) => out.extend_from_slice(&v.to_bits().to_be_bytes()),
        Nbt::ByteArray(v) => { out.extend_from_slice(&(v.len() as i32).to_be_bytes()); out.extend_from_slice(v); }
        Nbt::String(v) => write_string(out, v),
        Nbt::List(item, items) => {
            out.push(*item); out.extend_from_slice(&(items.len() as i32).to_be_bytes());
            for i in items { write_payload(out, i); }
        }
        Nbt::Compound(entries) => {
            for (name, value) in entries { out.push(value.id()); write_string(out, name); write_payload(out, value); }
            out.push(0);
        }
        Nbt::IntArray(v) => { out.extend_from_slice(&(v.len() as i32).to_be_bytes()); for i in v { out.extend_from_slice(&i.to_be_bytes()); } }
        Nbt::LongArray(v) => { out.extend_from_slice(&(v.len() as i32).to_be_bytes()); for i in v { out.extend_from_slice(&i.to_be_bytes()); } }
    }
}

/// Parses an uncompressed NBT file whose root is a named compound; returns (root name, compound).
pub fn parse_root(data: &[u8]) -> io::Result<(String, Nbt)> {
    let mut r = Reader { data, pos: 0 };
    if r.u8()? != 10 { return Err(bad("root is not a compound")); }
    let name = r.string()?;
    Ok((name, r.payload(10, 0)?))
}

pub fn write_root(name: &str, root: &Nbt) -> Vec<u8> {
    let mut out = vec![10];
    write_string(&mut out, name);
    write_payload(&mut out, root);
    out
}

fn get_string(entries: &[(String, Nbt)], key: &str) -> Option<String> {
    entries.iter().find(|(k, _)| k == key).and_then(|(_, v)| if let Nbt::String(s) = v { Some(s.clone()) } else { None })
}

/// Adds `name`/`ip` to the front of the server list unless that address is already present. Returns true if the file changed.
pub fn add_server(root: &mut Nbt, name: &str, ip: &str) -> bool {
    let Nbt::Compound(entries) = root else { return false };
    if !entries.iter().any(|(k, _)| k == "servers") { entries.push(("servers".into(), Nbt::List(10, Vec::new()))); }
    let list = entries.iter_mut().find(|(k, _)| k == "servers").map(|(_, v)| v).unwrap();
    if !matches!(list, Nbt::List(..)) { *list = Nbt::List(10, Vec::new()); }
    let Nbt::List(item, servers) = list else { return false };
    if *item != 10 { servers.clear(); *item = 10; }
    let exists = servers.iter().any(|s| matches!(s, Nbt::Compound(e) if get_string(e, "ip").map(|v| v.eq_ignore_ascii_case(ip)).unwrap_or(false)));
    if exists { return false; }
    servers.insert(0, Nbt::Compound(vec![("ip".into(), Nbt::String(ip.into())), ("name".into(), Nbt::String(name.into()))]));
    true
}

/// Ensures `<game_dir>/servers.dat` contains the given server. Existing entries are preserved.
pub fn ensure_default_server(game_dir: &Path, name: &str, ip: &str) -> io::Result<bool> {
    let path = game_dir.join("servers.dat");
    let mut root = match fs::read(&path) {
        Ok(bytes) => match parse_root(&bytes) {
            Ok((_, root)) => root,
            Err(_) => { let _ = fs::copy(&path, game_dir.join("servers.dat.bak")); Nbt::Compound(Vec::new()) }
        },
        Err(_) => Nbt::Compound(Vec::new()),
    };
    if !add_server(&mut root, name, ip) && path.exists() { return Ok(false); }
    fs::create_dir_all(game_dir)?;
    let tmp = game_dir.join("servers.dat.tmp");
    fs::write(&tmp, write_root("", &root))?;
    fs::rename(&tmp, &path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_preserves_entries() {
        let mut root = Nbt::Compound(Vec::new());
        assert!(add_server(&mut root, "Gorizont", "mc.gorizont.fun:20054"));
        assert!(!add_server(&mut root, "Gorizont", "MC.GORIZONT.FUN:20054"));
        // Pre-existing server with an extra field must survive a round trip.
        if let Nbt::Compound(e) = &mut root { if let Some((_, Nbt::List(_, s))) = e.iter_mut().find(|(k, _)| k == "servers") { s.push(Nbt::Compound(vec![("ip".into(), Nbt::String("other".into())), ("hidden".into(), Nbt::Byte(1))])); } }
        let bytes = write_root("", &root);
        let (name, parsed) = parse_root(&bytes).unwrap();
        assert_eq!(name, "");
        assert_eq!(parsed, root);
        let Nbt::Compound(e) = parsed else { panic!() };
        let Nbt::List(10, s) = &e[0].1 else { panic!() };
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn rejects_garbage() { assert!(parse_root(&[1, 2, 3]).is_err()); }
}
