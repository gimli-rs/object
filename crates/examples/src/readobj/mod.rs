use std::io::Write;
use std::{fmt, str};

use object::read::archive::ArchiveFile;
use object::read::macho::{FatArch, FatHeader};
use object::Endianness;

pub fn print(w: &'_ mut dyn Write, e: &'_ mut dyn Write, file: &[u8]) {
    let mut printer = Printer::new(w, e);
    print_object(&mut printer, file);
}

struct Printer<'a> {
    w: &'a mut dyn Write,
    e: &'a mut dyn Write,
    indent: usize,
}

impl<'a> Printer<'a> {
    fn new(w: &'a mut dyn Write, e: &'a mut dyn Write) -> Self {
        Self { w, e, indent: 0 }
    }

    fn w(&mut self) -> &mut dyn Write {
        self.w
    }

    fn blank(&mut self) {
        writeln!(self.w).unwrap();
    }

    fn print_indent(&mut self) {
        if self.indent != 0 {
            write!(self.w, "{:-1$}", " ", self.indent * 4).unwrap();
        }
    }

    fn print_string(&mut self, s: &[u8]) {
        if let Ok(s) = str::from_utf8(s) {
            write!(self.w, "\"{}\"", s).unwrap();
        } else {
            write!(self.w, "{:X?}", s).unwrap();
        }
    }

    fn indent<F: FnOnce(&mut Self)>(&mut self, f: F) {
        self.indent += 1;
        f(self);
        self.indent -= 1;
    }

    fn group<F: FnOnce(&mut Self)>(&mut self, name: &str, f: F) {
        self.print_indent();
        writeln!(self.w, "{} {{", name).unwrap();
        self.indent(f);
        self.print_indent();
        writeln!(self.w, "}}").unwrap();
    }

    fn field_name(&mut self, name: &str) {
        self.print_indent();
        if !name.is_empty() {
            write!(self.w, "{}: ", name).unwrap();
        }
    }

    fn field<T: fmt::Display>(&mut self, name: &str, value: T) {
        self.field_name(name);
        writeln!(self.w, "{}", value).unwrap();
    }

    fn field_hex<T: fmt::UpperHex>(&mut self, name: &str, value: T) {
        self.field_name(name);
        writeln!(self.w, "0x{:X}", value).unwrap();
    }

    fn field_bytes(&mut self, name: &str, value: &[u8]) {
        self.field_name(name);
        writeln!(self.w, "{:X?}", value).unwrap();
    }

    fn field_string_option<T: fmt::UpperHex>(&mut self, name: &str, value: T, s: Option<&[u8]>) {
        if let Some(s) = s {
            self.field_name(name);
            self.print_string(s);
            writeln!(self.w, " (0x{:X})", value).unwrap();
        } else {
            self.field_hex(name, value);
        }
    }

    fn field_string<T: fmt::UpperHex, E: fmt::Display>(
        &mut self,
        name: &str,
        value: T,
        s: Result<&[u8], E>,
    ) {
        let s = s.print_err(self);
        self.field_string_option(name, value, s);
    }

    fn field_inline_string(&mut self, name: &str, s: &[u8]) {
        self.field_name(name);
        self.print_string(s);
        writeln!(self.w).unwrap();
    }

    fn field_enum<T: Eq + fmt::UpperHex>(&mut self, name: &str, value: T, flags: &[Flag<T>]) {
        for flag in flags {
            if value == flag.value {
                self.field_name(name);
                writeln!(self.w, "{} (0x{:X})", flag.name, value).unwrap();
                return;
            }
        }
        self.field_hex(name, value);
    }

    fn field_enum_display<T: Eq + fmt::Display>(
        &mut self,
        name: &str,
        value: T,
        flags: &[Flag<T>],
    ) {
        for flag in flags {
            if value == flag.value {
                self.field_name(name);
                writeln!(self.w, "{} ({})", flag.name, value).unwrap();
                return;
            }
        }
        self.field(name, value);
    }

    fn field_enums<T: Eq + fmt::UpperHex>(&mut self, name: &str, value: T, enums: &[&[Flag<T>]]) {
        for flags in enums {
            for flag in *flags {
                if value == flag.value {
                    self.field_name(name);
                    writeln!(self.w, "{} (0x{:X})", flag.name, value).unwrap();
                    return;
                }
            }
        }
        self.field_hex(name, value);
    }

    fn flags<T: Into<u64>, U: Copy + Into<u64>>(&mut self, value: T, mask: U, flags: &[Flag<U>]) {
        let value = value.into();
        let mask = mask.into();
        self.indent(|p| {
            if mask != 0 {
                for flag in flags {
                    if value & mask == flag.value.into() {
                        p.print_indent();
                        writeln!(p.w, "{} (0x{:X})", flag.name, flag.value.into()).unwrap();
                        return;
                    }
                }
                p.print_indent();
                writeln!(p.w, "<unknown> (0x{:X})", value & mask).unwrap();
            } else {
                for flag in flags {
                    if value & flag.value.into() == flag.value.into() {
                        p.print_indent();
                        writeln!(p.w, "{} (0x{:X})", flag.name, flag.value.into()).unwrap();
                    }
                }
                // TODO: display unknown flags (need to display all flags at once for this)
            }
        });
    }
}

struct Flag<T> {
    value: T,
    name: &'static str,
}

macro_rules! flags {
    ($($name:ident),+ $(,)?) => ( [ $(Flag { value: $name, name: stringify!($name), }),+ ] )
}

fn print_object(p: &mut Printer<'_>, data: &[u8]) {
    let kind = match object::FileKind::parse(data) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to parse file: {}", err);
            return;
        }
    };
    match kind {
        object::FileKind::Archive => print_archive(p, data),
        object::FileKind::Coff => pe::print_coff(p, data),
        object::FileKind::CoffBig => pe::print_coff_big(p, data),
        object::FileKind::DyldCache => macho::print_dyld_cache(p, data),
        object::FileKind::Elf32 => elf::print_elf32(p, data),
        object::FileKind::Elf64 => elf::print_elf64(p, data),
        object::FileKind::MachO32 => macho::print_macho32(p, data, 0),
        object::FileKind::MachO64 => macho::print_macho64(p, data, 0),
        object::FileKind::MachOFat32 => macho::print_macho_fat32(p, data),
        object::FileKind::MachOFat64 => macho::print_macho_fat64(p, data),
        object::FileKind::Pe32 => pe::print_pe32(p, data),
        object::FileKind::Pe64 => pe::print_pe64(p, data),
        // TODO
        _ => {}
    }
}

fn print_object_at(p: &mut Printer<'_>, data: &[u8], offset: u64) {
    let kind = match object::FileKind::parse_at(data, offset) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to parse file: {}", err);
            return;
        }
    };
    match kind {
        object::FileKind::MachO32 => macho::print_macho32(p, data, offset),
        object::FileKind::MachO64 => macho::print_macho64(p, data, offset),
        // TODO
        _ => {}
    }
}

fn print_archive(p: &mut Printer<'_>, data: &[u8]) {
    if let Some(archive) = ArchiveFile::parse(data).print_err(p) {
        p.field("Format", format!("Archive ({:?})", archive.kind()));
        for member in archive.members() {
            if let Some(member) = member.print_err(p) {
                p.blank();
                p.field("Member", String::from_utf8_lossy(member.name()));
                if let Some(data) = member.data(data).print_err(p) {
                    print_object(p, data);
                }
            }
        }
    }
}

trait PrintErr<T> {
    fn print_err(self, p: &mut Printer<'_>) -> Option<T>;
}

impl<T, E: fmt::Display> PrintErr<T> for Result<T, E> {
    fn print_err(self, p: &mut Printer<'_>) -> Option<T> {
        match self {
            Ok(val) => Some(val),
            Err(err) => {
                writeln!(p.e, "Error: {}", err).unwrap();
                None
            }
        }
    }
}

mod elf;
mod macho;
mod pe;
